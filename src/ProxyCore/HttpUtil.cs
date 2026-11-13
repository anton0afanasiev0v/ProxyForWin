using System.Text;

namespace ProxyForWin.Core;

/// <summary>Small helpers for the tiny HTTP bits the local proxy needs.</summary>
public static class HttpUtil
{
    public const int MaxHeaderBytes = 32 * 1024;

    private static readonly string[] Methods =
    {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    };

    public static bool LooksLikeHttpRequest(ReadOnlySpan<byte> data)
    {
        foreach (var method in Methods)
        {
            if (data.Length >= method.Length && data[..method.Length].SequenceEqual(Encoding.ASCII.GetBytes(method)))
            {
                return true;
            }
        }

        return false;
    }

    public static int IndexOfHeaderEnd(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i + 3 < data.Length; i++)
        {
            if (data[i] == (byte)'\r' && data[i + 1] == (byte)'\n' && data[i + 2] == (byte)'\r' && data[i + 3] == (byte)'\n')
            {
                return i + 4;
            }
        }

        return -1;
    }

    public static string? GetHeader(string headers, string name)
    {
        foreach (var line in headers.Split("\r\n"))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            if (line.AsSpan(0, colon).Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return line[(colon + 1)..].Trim();
            }
        }

        return null;
    }

    /// <summary>Returns (host, port) from a CONNECT authority or an absolute URI.</summary>
    public static bool TryParseAuthority(string authority, int defaultPort, out string host, out int port)
    {
        host = string.Empty;
        port = defaultPort;

        authority = authority.Trim();
        if (authority.Length == 0)
        {
            return false;
        }

        // IPv6 literal: [::1]:443
        if (authority[0] == '[')
        {
            var close = authority.IndexOf(']');
            if (close < 0)
            {
                return false;
            }

            host = authority[1..close];
            var rest = authority[(close + 1)..];
            if (rest.StartsWith(':'))
            {
                return int.TryParse(rest[1..], out port) && port is > 0 and <= 65535;
            }

            return true;
        }

        var colon = authority.LastIndexOf(':');
        if (colon > 0 && authority.IndexOf(':') == colon)
        {
            host = authority[..colon];
            return int.TryParse(authority[(colon + 1)..], out port) && port is > 0 and <= 65535;
        }

        host = authority;
        return host.Length > 0;
    }

    /// <summary>Extracts host/port from "http://host:port/path".</summary>
    public static bool TryParseAbsoluteUri(string uri, out string host, out int port)
    {
        host = string.Empty;
        port = 0;

        var schemeEnd = uri.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd <= 0)
        {
            return false;
        }

        var defaultPort = uri[..schemeEnd].Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80;
        var rest = uri[(schemeEnd + 3)..];
        var slash = rest.IndexOfAny(new[] { '/', '?', '#' });
        var authority = slash >= 0 ? rest[..slash] : rest;
        return TryParseAuthority(authority, defaultPort, out host, out port);
    }

    public static string BuildBasicAuth(string user, string password)
        => "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + password));
}
