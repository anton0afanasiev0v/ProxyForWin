using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProxyForWin.Core;

/// <summary>Loads and saves <see cref="ProxySettings"/>, encrypting the password.</summary>
public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _path;
    private readonly ISecretProtector _protector;
    private readonly Logger? _log;

    public SettingsStore(string path, ISecretProtector protector, Logger? log = null)
    {
        _path = path;
        _protector = protector;
        _log = log;
    }

    public string Path => _path;

    public ProxySettings Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return ProxySettings.CreateDefault();
            }

            var dto = JsonSerializer.Deserialize<SettingsDto>(File.ReadAllText(_path), JsonOptions);
            if (dto is null)
            {
                return ProxySettings.CreateDefault();
            }

            var settings = dto.ToSettings();
            if (!string.IsNullOrEmpty(dto.Password))
            {
                try
                {
                    settings.Password = _protector.Unprotect(dto.Password);
                }
                catch (Exception ex)
                {
                    settings.Password = string.Empty;
                    _log?.Warn("Не удалось расшифровать пароль (DPAPI): " + ex.Message +
                               ". Укажите пароль в настройках заново.");
                }
            }

            return settings;
        }
        catch (Exception ex)
        {
            _log?.Warn("Не удалось прочитать настройки из " + _path + ": " + ex.Message +
                       ". Используются значения по умолчанию.");
            return ProxySettings.CreateDefault();
        }
    }

    public void Save(ProxySettings settings)
    {
        var directory = System.IO.Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var dto = SettingsDto.FromSettings(settings);
        dto.Password = string.IsNullOrEmpty(settings.Password) ? string.Empty : _protector.Protect(settings.Password);

        var temp = _path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(dto, JsonOptions));
        File.Move(temp, _path, overwrite: true);
    }

    private sealed class SettingsDto
    {
        public string UpstreamHost { get; set; } = "";
        public int UpstreamPort { get; set; } = 8080;
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public int ListenPort { get; set; } = 8899;
        public ProxyMode Mode { get; set; }
        public bool ApplyWinHttp { get; set; } = true;
        public bool BlockQuic { get; set; } = true;
        public bool BlockIpv6 { get; set; } = true;
        public bool RunAtLogon { get; set; }
        public bool StartMinimized { get; set; } = true;
        public bool EnableOnStartup { get; set; }
        public bool VerboseLog { get; set; }
        public List<string> Bypass { get; set; } = new();
        public List<string> VpnEndpoints { get; set; } = new();

        public ProxySettings ToSettings() => new()
        {
            UpstreamHost = UpstreamHost,
            UpstreamPort = UpstreamPort,
            Username = Username,
            Password = Password,
            ListenPort = ListenPort,
            Mode = Mode,
            ApplyWinHttp = ApplyWinHttp,
            BlockQuic = BlockQuic,
            BlockIpv6 = BlockIpv6,
            RunAtLogon = RunAtLogon,
            StartMinimized = StartMinimized,
            EnableOnStartup = EnableOnStartup,
            VerboseLog = VerboseLog,
            Bypass = Bypass ?? new List<string>(),
            VpnEndpoints = VpnEndpoints ?? new List<string>(),
        };

        public static SettingsDto FromSettings(ProxySettings s) => new()
        {
            UpstreamHost = s.UpstreamHost,
            UpstreamPort = s.UpstreamPort,
            Username = s.Username,
            Password = s.Password,
            ListenPort = s.ListenPort,
            Mode = s.Mode,
            ApplyWinHttp = s.ApplyWinHttp,
            BlockQuic = s.BlockQuic,
            BlockIpv6 = s.BlockIpv6,
            RunAtLogon = s.RunAtLogon,
            StartMinimized = s.StartMinimized,
            EnableOnStartup = s.EnableOnStartup,
            VerboseLog = s.VerboseLog,
            Bypass = s.Bypass,
            VpnEndpoints = s.VpnEndpoints,
        };
    }
}
