using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using ProxyForWin.Core;

namespace ProxyForWin.Tray;

/// <summary>
/// Applies and restores the Windows-wide proxy:
///   * WinINET (Edge, Chrome, IE, most desktop apps) via HKCU internet settings;
///   * WinHTTP (services, svchost, Windows Update) via WinHttpSetDefaultProxyConfiguration.
///
/// The original values are snapshotted to disk before the first change and restored
/// on stop, on exit, and on the next start after a crash.
/// </summary>
public sealed class SystemProxyManager
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionRefresh = 37;
    private const int InternetOptionSettingsChanged = 39;
    private const uint AccessTypeNoProxy = 1;
    private const uint AccessTypeNamedProxy = 3;

    private readonly Logger _log;
    private readonly string _statePath;

    public SystemProxyManager(string statePath, Logger log)
    {
        _statePath = statePath;
        _log = log;
    }

    public sealed class Snapshot
    {
        public bool Active { get; set; }
        public int? ProxyEnable { get; set; }
        public string? ProxyServer { get; set; }
        public string? ProxyOverride { get; set; }
        public int? AutoDetect { get; set; }
        public bool AutoConfigExisted { get; set; }
        public string? AutoConfigUrl { get; set; }
        public uint WinHttpAccessType { get; set; } = AccessTypeNoProxy;
        public string? WinHttpProxy { get; set; }
        public string? WinHttpBypass { get; set; }
    }

    public void Apply(int listenPort, BypassList bypass, bool applyWinHttp)
    {
        var snapshot = LoadSnapshot();
        if (snapshot is null || !snapshot.Active)
        {
            snapshot = Capture();
            snapshot.Active = true;
            SaveSnapshot(snapshot);
            _log.Info("Сохранены исходные настройки прокси Windows");
        }

        var proxyServer = $"127.0.0.1:{listenPort}";
        var overrideList = bypass.ToWinInetOverride();

        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
                        ?? Registry.CurrentUser.CreateSubKey(InternetSettingsKey);
        if (key is null)
        {
            throw new InvalidOperationException("Не удалось открыть ветку реестра настроек интернета.");
        }

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
        key.SetValue("ProxyOverride", overrideList, RegistryValueKind.String);
        key.SetValue("AutoDetect", 0, RegistryValueKind.DWord);
        try
        {
            key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
        }
        catch
        {
            // ignored
        }

        NotifyWinInet();

        if (applyWinHttp)
        {
            try
            {
                SetWinHttp(proxyServer, overrideList);
                _log.Info("Прокси WinHTTP настроен: " + proxyServer);
            }
            catch (Exception ex)
            {
                _log.Warn("Не удалось настроить WinHTTP: " + ex.Message);
            }
        }

        _log.Info($"Системный прокси включён: {proxyServer}");
    }

    public void Restore()
    {
        var snapshot = LoadSnapshot();
        if (snapshot is null || !snapshot.Active)
        {
            return;
        }

        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true))
            {
                if (key is not null)
                {
                    RestoreValue(key, "ProxyEnable", snapshot.ProxyEnable, RegistryValueKind.DWord);
                    RestoreValue(key, "ProxyServer", snapshot.ProxyServer, RegistryValueKind.String);
                    RestoreValue(key, "ProxyOverride", snapshot.ProxyOverride, RegistryValueKind.String);
                    RestoreValue(key, "AutoDetect", snapshot.AutoDetect, RegistryValueKind.DWord);

                    if (snapshot.AutoConfigExisted)
                    {
                        key.SetValue("AutoConfigURL", snapshot.AutoConfigUrl ?? string.Empty, RegistryValueKind.String);
                    }
                    else
                    {
                        key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
                    }
                }
            }

            NotifyWinInet();
            RestoreWinHttp(snapshot);
            _log.Info("Исходные настройки прокси Windows восстановлены");
        }
        catch (Exception ex)
        {
            _log.Error("Ошибка восстановления настроек прокси: " + ex.Message);
        }
        finally
        {
            snapshot.Active = false;
            SaveSnapshot(snapshot);
        }
    }

    /// <summary>Restores settings left behind by a previous crash or forced kill.</summary>
    public void RestorePending()
    {
        var snapshot = LoadSnapshot();
        if (snapshot is { Active: true })
        {
            _log.Warn("Обнаружены незакрытые настройки прокси, восстанавливаю");
            Restore();
        }
    }

    private static void RestoreValue(RegistryKey key, string name, object? value, RegistryValueKind kind)
    {
        if (value is null)
        {
            key.DeleteValue(name, throwOnMissingValue: false);
            return;
        }

        key.SetValue(name, value, kind);
    }

    private Snapshot Capture()
    {
        var snapshot = new Snapshot();

        using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey))
        {
            if (key is not null)
            {
                snapshot.ProxyEnable = key.GetValue("ProxyEnable") as int?;
                snapshot.ProxyServer = key.GetValue("ProxyServer") as string;
                snapshot.ProxyOverride = key.GetValue("ProxyOverride") as string;
                snapshot.AutoDetect = key.GetValue("AutoDetect") as int?;
                var autoConfig = key.GetValue("AutoConfigURL") as string;
                snapshot.AutoConfigExisted = autoConfig is not null;
                snapshot.AutoConfigUrl = autoConfig;
            }
        }

        try
        {
            GetWinHttp(out var accessType, out var proxy, out var bypass);
            snapshot.WinHttpAccessType = accessType;
            snapshot.WinHttpProxy = proxy;
            snapshot.WinHttpBypass = bypass;
        }
        catch
        {
            snapshot.WinHttpAccessType = AccessTypeNoProxy;
        }

        return snapshot;
    }

    private Snapshot? LoadSnapshot()
    {
        try
        {
            if (!File.Exists(_statePath))
            {
                return null;
            }

            return JsonSerializer.Deserialize<Snapshot>(File.ReadAllText(_statePath));
        }
        catch
        {
            return null;
        }
    }

    private void SaveSnapshot(Snapshot snapshot)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            File.WriteAllText(_statePath, JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            _log.Warn("Не удалось сохранить состояние прокси: " + ex.Message);
        }
    }

    private static void NotifyWinInet()
    {
        InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
    }

    private static void GetWinHttp(out uint accessType, out string? proxy, out string? bypass)
    {
        accessType = AccessTypeNoProxy;
        proxy = null;
        bypass = null;

        if (!WinHttpGetDefaultProxyConfiguration(out var info))
        {
            return;
        }

        try
        {
            accessType = info.AccessType;
            proxy = info.Proxy == IntPtr.Zero ? null : Marshal.PtrToStringUni(info.Proxy);
            bypass = info.ProxyBypass == IntPtr.Zero ? null : Marshal.PtrToStringUni(info.ProxyBypass);
        }
        finally
        {
            if (info.Proxy != IntPtr.Zero)
            {
                GlobalFree(info.Proxy);
            }

            if (info.ProxyBypass != IntPtr.Zero)
            {
                GlobalFree(info.ProxyBypass);
            }
        }
    }

    private static void SetWinHttp(string proxy, string bypass)
    {
        var info = new WinHttpProxyInfo
        {
            AccessType = AccessTypeNamedProxy,
            Proxy = Marshal.StringToHGlobalUni(proxy),
            ProxyBypass = IntPtr.Zero,
        };

        try
        {
            if (!string.IsNullOrEmpty(bypass))
            {
                info.ProxyBypass = Marshal.StringToHGlobalUni(bypass);
            }

            if (!WinHttpSetDefaultProxyConfiguration(ref info))
            {
                throw new InvalidOperationException("WinHttpSetDefaultProxyConfiguration, код " + Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            if (info.Proxy != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(info.Proxy);
            }

            if (info.ProxyBypass != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(info.ProxyBypass);
            }
        }
    }

    private static void RestoreWinHttp(Snapshot snapshot)
    {
        var info = new WinHttpProxyInfo { AccessType = snapshot.WinHttpAccessType };
        try
        {
            if (snapshot.WinHttpAccessType == AccessTypeNamedProxy && !string.IsNullOrEmpty(snapshot.WinHttpProxy))
            {
                info.Proxy = Marshal.StringToHGlobalUni(snapshot.WinHttpProxy);
                if (!string.IsNullOrEmpty(snapshot.WinHttpBypass))
                {
                    info.ProxyBypass = Marshal.StringToHGlobalUni(snapshot.WinHttpBypass);
                }
            }

            WinHttpSetDefaultProxyConfiguration(ref info);
        }
        finally
        {
            if (info.Proxy != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(info.Proxy);
            }

            if (info.ProxyBypass != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(info.ProxyBypass);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinHttpProxyInfo
    {
        public uint AccessType;
        public IntPtr Proxy;
        public IntPtr ProxyBypass;
    }

    [DllImport("winhttp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(out WinHttpProxyInfo info);

    [DllImport("winhttp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpSetDefaultProxyConfiguration(ref WinHttpProxyInfo info);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalFree(IntPtr memory);

    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr buffer, int bufferLength);
}
