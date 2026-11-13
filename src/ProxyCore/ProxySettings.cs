using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProxyForWin.Core;

public enum ProxyMode
{
    /// <summary>Configure the Windows system proxy (WinINET + WinHTTP).</summary>
    SystemProxy = 0,

    /// <summary>Redirect every TCP connection through the local proxy using WinDivert.</summary>
    FullTraffic = 1,
}

/// <summary>
/// Everything the user can configure. Persisted as JSON; the password is stored
/// through an <see cref="ISecretProtector"/>.
/// </summary>
public sealed class ProxySettings
{
    public string UpstreamHost { get; set; } = "";

    public int UpstreamPort { get; set; } = 8080;

    public string Username { get; set; } = "";

    public string Password { get; set; } = "";

    /// <summary>Local port the built-in proxy listens on.</summary>
    public int ListenPort { get; set; } = 8899;

    public ProxyMode Mode { get; set; } = ProxyMode.SystemProxy;

    /// <summary>Also configure the WinHTTP proxy (services, svchost, Windows Update).</summary>
    public bool ApplyWinHttp { get; set; } = true;

    /// <summary>Drop outbound UDP/443 (QUIC) so apps fall back to TCP.</summary>
    public bool BlockQuic { get; set; } = true;

    /// <summary>Drop outbound IPv6 in full-traffic mode (HTTP CONNECT cannot carry it).</summary>
    public bool BlockIpv6 { get; set; } = true;

    /// <summary>Add the app to Task Scheduler autostart (highest privileges).</summary>
    public bool RunAtLogon { get; set; } = false;

    public bool StartMinimized { get; set; } = true;

    /// <summary>Turn the proxy on automatically when the app starts.</summary>
    public bool EnableOnStartup { get; set; } = false;

    /// <summary>Domains / IPs / CIDRs that always go direct, bypassing the proxy.</summary>
    public List<string> Bypass { get; set; } = new();

    [JsonIgnore]
    public bool HasUpstream => !string.IsNullOrWhiteSpace(UpstreamHost) && UpstreamPort is > 0 and <= 65535;

    [JsonIgnore]
    public string UpstreamEndpoint => $"{UpstreamHost}:{UpstreamPort}";

    public ProxySettings Clone()
        => JsonSerializer.Deserialize<ProxySettings>(JsonSerializer.Serialize(this))!;

    public static ProxySettings CreateDefault() => new()
    {
        UpstreamHost = "",
        UpstreamPort = 8080,
        ListenPort = 8899,
        Mode = ProxyMode.SystemProxy,
        ApplyWinHttp = true,
        BlockQuic = true,
        BlockIpv6 = true,
        StartMinimized = true,
        Bypass = new List<string>
        {
            "localhost",
            "*.local",
            "*.lan",
            "*.home.arpa",
        },
    };
}
