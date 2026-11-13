using System.Net.Sockets;
using ProxyForWin.Core;
using ProxyForWin.Core.WinDivert;

namespace ProxyForWin.Tray;

/// <summary>Orchestrates the local proxy, the Windows proxy settings and WinDivert.</summary>
public sealed class ProxyEngine : IDisposable
{
    private readonly Logger _log;
    private readonly SystemProxyManager _systemProxy;
    private readonly object _gate = new();

    private ProxySettings _settings;
    private LocalProxyServer? _proxy;
    private NatTable? _nat;
    private Redirector? _redirector;
    private SelfConnectionRegistry _selfConnections = new();
    private bool _firewallRuleActive;

    public ProxyEngine(ProxySettings settings, SystemProxyManager systemProxy, Logger log)
    {
        _settings = settings;
        _systemProxy = systemProxy;
        _log = log;
    }

    public event Action? Changed;

    public bool IsRunning { get; private set; }

    public ProxyMode? ActiveMode { get; private set; }

    public ProxySettings Settings => _settings;

    public LocalProxyServer? Proxy => _proxy;

    public Redirector? Redirector => _redirector;

    public string StatusText
    {
        get
        {
            if (!IsRunning)
            {
                return "Выключен";
            }

            return ActiveMode == ProxyMode.FullTraffic
                ? "Весь трафик через прокси"
                : "Системный прокси включён";
        }
    }

    /// <summary>Compact one-line summary for the tray tooltip, refreshed by a timer.</summary>
    public string StatsText
    {
        get
        {
            var proxy = _proxy;
            if (proxy is null)
            {
                return string.Empty;
            }

            var text = $"TCP: {proxy.TotalConnections} (активно {proxy.ActiveConnections}), " +
                       $"трафик {FormatBytes(proxy.BytesUp)}↑ / {FormatBytes(proxy.BytesDown)}↓";

            var redirector = _redirector;
            if (redirector is not null)
            {
                text += $", UDP-блок: {redirector.DroppedQuic}, " +
                        $"IPv6-блок: {redirector.DroppedIpv6}, VPN-пропуск: {redirector.PassedVpnPackets}";
            }

            return text;
        }
    }

    private static string FormatBytes(long bytes)
    {
        const long kb = 1024;
        const long mb = kb * 1024;
        const long gb = mb * 1024;

        return bytes switch
        {
            >= gb => $"{bytes / (double)gb:F1} ГБ",
            >= mb => $"{bytes / (double)mb:F1} МБ",
            >= kb => $"{bytes / (double)kb:F0} КБ",
            _ => $"{bytes} Б",
        };
    }

    public async Task StartAsync()
    {
        lock (_gate)
        {
            if (IsRunning)
            {
                return;
            }
        }

        if (!_settings.HasUpstream)
        {
            throw new InvalidOperationException("Укажите адрес и порт прокси-сервера в настройках.");
        }

        var settings = _settings.Clone();
        _log.Verbose = settings.VerboseLog;

        var bypass = new BypassList(settings.Bypass);
        // VPN endpoints are an explicit list: private ranges must not be exempt from
        // the QUIC/IPv6 blockers unless the user actually named them.
        var vpn = new BypassList(settings.VpnEndpoints, includePrivateRanges: false);
        var nat = settings.Mode == ProxyMode.FullTraffic ? new NatTable() : null;
        var selfConnections = new SelfConnectionRegistry();
        var proxy = new LocalProxyServer(settings, bypass, _log, nat, vpn, selfConnections);

        await proxy.StartAsync().ConfigureAwait(false);

        LogEffectiveConfig(settings, vpn);

        try
        {
            if (settings.Mode == ProxyMode.FullTraffic)
            {
                var redirector = new Redirector(settings, bypass, vpn, nat!, selfConnections, _log);
                redirector.Start();
                _redirector = redirector;
                FirewallManager.EnsureRule(settings.ListenPort, _log);
                _firewallRuleActive = true;
                _log.Info("Режим: весь трафик (WinDivert)");
            }
            else
            {
                _log.Info("Режим: системный прокси Windows");
            }

            // The system proxy is configured in both modes: apps that respect it go
            // straight to 127.0.0.1 (with the host name), the rest are reflected by
            // WinDivert. This also gives WinINET its own bypass list.
            _systemProxy.Apply(settings.ListenPort, bypass, settings.ApplyWinHttp);

            lock (_gate)
            {
                _settings = settings;
                _proxy = proxy;
                _nat = nat;
                _selfConnections = selfConnections;
                IsRunning = true;
                ActiveMode = settings.Mode;
            }

            _log.Info($"Прокси включён. Upstream: {settings.UpstreamEndpoint}");
        }
        catch
        {
            try
            {
                _redirector?.Dispose();
                _redirector = null;
                if (_firewallRuleActive)
                {
                    FirewallManager.RemoveRule();
                    _firewallRuleActive = false;
                }

                _systemProxy.Restore();
                await proxy.StopAsync().ConfigureAwait(false);
                await proxy.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // ignored
            }

            throw;
        }

        Changed?.Invoke();
    }

    /// <summary>
    /// Writes the effective configuration once at startup. Credentials are never
    /// logged — only whether they are set — and IPv6 addresses are counted, not printed.
    /// </summary>
    private void LogEffectiveConfig(ProxySettings settings, BypassList vpn)
    {
        var login = string.IsNullOrEmpty(settings.Username) ? "не задан" : "задан";
        var password = string.IsNullOrEmpty(settings.Password) ? "не задан" : "задан";

        _log.Info($"Настройки: upstream {settings.UpstreamEndpoint}, " +
                  $"логин {login}, пароль {password}, локальный порт {settings.ListenPort}");
        _log.Info($"Исключения: {settings.Bypass.Count}, VPN-серверы: {settings.VpnEndpoints.Count}" +
                  (vpn.Count == 0
                      ? " (UDP/443 и IPv6 для VPN будут блокироваться)"
                      : string.Empty));
        _log.Info($"QUIC (UDP/443): {(settings.BlockQuic ? "блокируется" : "разрешён")}, " +
                  $"IPv6: {(settings.BlockIpv6 ? "блокируется" : "разрешён")}, " +
                  $"подробный журнал: {(settings.VerboseLog ? "включён" : "выключен")}");
    }

    public async Task StopAsync()
    {
        Redirector? redirector;
        LocalProxyServer? proxy;

        lock (_gate)
        {
            if (!IsRunning && _proxy is null)
            {
                return;
            }

            redirector = _redirector;
            proxy = _proxy;
            _redirector = null;
            _proxy = null;
            _nat = null;
            IsRunning = false;
            ActiveMode = null;
        }

        try
        {
            redirector?.Dispose();
        }
        catch (Exception ex)
        {
            _log.Warn("Ошибка остановки перехвата: " + ex.Message);
        }

        if (_firewallRuleActive)
        {
            FirewallManager.RemoveRule();
            _firewallRuleActive = false;
        }

        try
        {
            _systemProxy.Restore();
        }
        catch (Exception ex)
        {
            _log.Warn("Ошибка восстановления системного прокси: " + ex.Message);
        }

        if (proxy is not null)
        {
            await proxy.StopAsync().ConfigureAwait(false);
            await proxy.DisposeAsync().ConfigureAwait(false);
        }

        _log.Info("Прокси выключен");
        Changed?.Invoke();
    }

    public async Task ApplyAsync(ProxySettings settings)
    {
        var wasRunning = IsRunning;
        if (wasRunning)
        {
            await StopAsync().ConfigureAwait(false);
        }

        _settings = settings;
        _log.Verbose = settings.VerboseLog;

        if (wasRunning)
        {
            await StartAsync().ConfigureAwait(false);
        }
        else
        {
            Changed?.Invoke();
        }
    }

    /// <summary>Checks that the upstream proxy accepts CONNECT and requires the given credentials.</summary>
    public async Task<TimeSpan> TestUpstreamAsync(CancellationToken ct)
        => await TestUpstreamAsync(_settings, ct).ConfigureAwait(false);

    public async Task<TimeSpan> TestUpstreamAsync(ProxySettings settings, CancellationToken ct)
    {
        if (!settings.HasUpstream)
        {
            throw new InvalidOperationException("Прокси-сервер не задан.");
        }

        var connector = new UpstreamConnector(settings, _log, _selfConnections);
        var started = DateTime.UtcNow;
        using var tunnel = await connector.ConnectAsync("www.google.com", 443, useUpstream: true, ct).ConfigureAwait(false);
        return DateTime.UtcNow - started;
    }

    public void Dispose()
    {
        try
        {
            StopAsync().GetAwaiter().GetResult();
        }
        catch
        {
            // ignored
        }
    }
}
