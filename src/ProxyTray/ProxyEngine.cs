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
        var bypass = new BypassList(settings.Bypass);
        var nat = settings.Mode == ProxyMode.FullTraffic ? new NatTable() : null;
        var proxy = new LocalProxyServer(settings, bypass, _log, nat);

        await proxy.StartAsync().ConfigureAwait(false);

        try
        {
            if (settings.Mode == ProxyMode.FullTraffic)
            {
                var redirector = new Redirector(settings, bypass, nat!, _log);
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

        var connector = new UpstreamConnector(settings, _log);
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
