using System.Net;
using System.Net.Sockets;

namespace ProxyForWin.Core;

/// <summary>
/// Matches hosts and IP addresses against the user's bypass list.
///
/// Supported entry formats:
///   example.com          exact host and all subdomains
///   *.example.com        subdomains only (glob)
///   *.corp.local         glob anywhere in the name
///   10.0.0.0/8           IPv4 CIDR
///   192.168.0.1          single IPv4 address
///   fc00::/7             IPv6 CIDR
///   # comment            ignored
/// </summary>
public sealed class BypassList
{
    private readonly List<string> _hostGlobs = new();
    private readonly List<string> _hostSuffixes = new();
    private readonly HashSet<string> _hostsExact = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(uint Network, int Prefix)> _ipv4 = new();
    private readonly List<(byte[] Network, int Prefix)> _ipv6 = new();

    public static BypassList Empty { get; } = new(Array.Empty<string>(), includePrivateRanges: false);

    public BypassList(IEnumerable<string>? entries, bool includePrivateRanges = true)
    {
        if (includePrivateRanges)
        {
            AddPrivateRanges();
        }

        foreach (var raw in entries ?? Array.Empty<string>())
        {
            Add(raw);
        }
    }

    public int Count => _hostGlobs.Count + _hostSuffixes.Count + _hostsExact.Count + _ipv4.Count + _ipv6.Count;

    public bool HasDomainRules => _hostGlobs.Count > 0 || _hostSuffixes.Count > 0 || _hostsExact.Count > 0;

    private void AddPrivateRanges()
    {
        // RFC1918 + link-local + loopback. These must never be sent to the proxy.
        Add("10.0.0.0/8");
        Add("172.16.0.0/12");
        Add("192.168.0.0/16");
        Add("169.254.0.0/16");
        Add("127.0.0.0/8");
        Add("::1/128");
        Add("fc00::/7");
        Add("fe80::/10");
        Add("224.0.0.0/4");
        Add("ff00::/8");
    }

    private void Add(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return;
        }

        var entry = raw.Trim();
        if (entry.StartsWith('#'))
        {
            return;
        }

        // Allow "<local>" (Windows syntax) — it is already covered by private ranges.
        if (entry.Equals("<local>", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Strip a scheme and a trailing path if somebody pasted a URL.
        var schemeIndex = entry.IndexOf("://", StringComparison.Ordinal);
        if (schemeIndex >= 0)
        {
            entry = entry[(schemeIndex + 3)..];
        }

        var slash = entry.IndexOf('/');
        if (slash > 0 && !IsCidr(entry))
        {
            // "example.com/path" -> "example.com"
            entry = entry[..slash];
        }

        if (entry.Length == 0)
        {
            return;
        }

        if (IsCidr(entry))
        {
            AddCidr(entry);
            return;
        }

        if (IPAddress.TryParse(entry.Trim('[', ']'), out var ip))
        {
            AddIp(ip);
            return;
        }

        // host[:port]
        var colon = entry.LastIndexOf(':');
        if (colon > 0 && entry.IndexOf(':') == colon)
        {
            entry = entry[..colon];
        }

        entry = entry.TrimEnd('.').ToLowerInvariant();
        if (entry.Length == 0)
        {
            return;
        }

        if (entry.Contains('*') || entry.Contains('?'))
        {
            _hostGlobs.Add(entry);
        }
        else
        {
            _hostsExact.Add(entry);
            _hostSuffixes.Add("." + entry);
        }
    }

    private static bool IsCidr(string s)
        => s.Contains('/') && s.Split('/', 2) is { Length: 2 } parts
           && int.TryParse(parts[1], out var p) && p >= 0 && p <= 128
           && IPAddress.TryParse(parts[0], out _);

    private void AddCidr(string cidr)
    {
        var parts = cidr.Split('/', 2);
        if (!IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out var prefix))
        {
            return;
        }

        AddIp(ip, prefix);
    }

    private void AddIp(IPAddress ip, int? prefix = null)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork && ip.GetAddressBytes().Length == 4)
        {
            var bytes = ip.GetAddressBytes();
            var value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            _ipv4.Add((value, prefix ?? 32));
            return;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            _ipv6.Add((ip.GetAddressBytes(), prefix ?? 128));
        }
    }

    public bool MatchesHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        host = host.Trim().TrimEnd('.').ToLowerInvariant();

        if (_hostsExact.Contains(host))
        {
            return true;
        }

        foreach (var suffix in _hostSuffixes)
        {
            if (host.EndsWith(suffix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        foreach (var glob in _hostGlobs)
        {
            if (GlobMatch(glob, host))
            {
                return true;
            }
        }

        return false;
    }

    public bool MatchesIp(IPAddress? ip)
    {
        if (ip is null)
        {
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            var value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            foreach (var (network, prefix) in _ipv4)
            {
                var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
                if ((value & mask) == (network & mask))
                {
                    return true;
                }
            }

            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var value = ip.GetAddressBytes();
            foreach (var (network, prefix) in _ipv6)
            {
                if (PrefixMatches(value, network, prefix))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool PrefixMatches(byte[] a, byte[] b, int prefix)
    {
        var full = prefix / 8;
        for (var i = 0; i < full; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        var rest = prefix % 8;
        if (rest == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - rest));
        return (a[full] & mask) == (b[full] & mask);
    }

    /// <summary>Case-insensitive glob: '*' matches any run of characters, '?' exactly one.</summary>
    public static bool GlobMatch(string pattern, string text)
    {
        var p = 0;
        var t = 0;
        var star = -1;
        var match = 0;

        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || pattern[p] == text[t]))
            {
                p++;
                t++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                match = t;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++match;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }

    /// <summary>Value for the WinINET ProxyOverride registry value.</summary>
    public string ToWinInetOverride()
    {
        var parts = new List<string> { "<local>" };
        parts.AddRange(_hostsExact);
        parts.AddRange(_hostGlobs);

        foreach (var (network, prefix) in _ipv4)
        {
            // WinINET understands only "*" wildcards, not CIDR. Express the
            // common prefix lengths as address wildcards; skip the rest.
            var a = (network >> 24) & 0xFF;
            var b = (network >> 16) & 0xFF;
            var c = (network >> 8) & 0xFF;
            var d = network & 0xFF;

            switch (prefix)
            {
                case 32:
                    parts.Add($"{a}.{b}.{c}.{d}");
                    break;
                case 24:
                    parts.Add($"{a}.{b}.{c}.*");
                    break;
                case 16:
                    parts.Add($"{a}.{b}.*");
                    break;
                case 12 when (b & 0xF0) == b && a is >= 172 and <= 172:
                    for (var i = b; i < b + 16; i++)
                    {
                        parts.Add($"{a}.{i}.*");
                    }

                    break;
                case 8:
                    parts.Add($"{a}.*");
                    break;
            }
        }

        return string.Join(";", parts.Distinct(StringComparer.OrdinalIgnoreCase));
    }
}
