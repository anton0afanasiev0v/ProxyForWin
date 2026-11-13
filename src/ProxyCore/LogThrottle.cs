using System.Collections.Concurrent;

namespace ProxyForWin.Core;

/// <summary>
/// Rate limits repeated log messages so a failing destination cannot flood the
/// journal (a blocked UDP/443 flow or a rejected CONNECT can fire thousands of
/// times per second).
/// </summary>
public sealed class LogThrottle
{
    private readonly ConcurrentDictionary<string, long> _last =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly long _intervalMs;

    public LogThrottle(TimeSpan interval)
        => _intervalMs = Math.Max(0, (long)interval.TotalMilliseconds);

    /// <summary>Returns true if this key has not been logged within the interval.</summary>
    public bool ShouldLog(string key)
    {
        var now = Environment.TickCount64;
        if (_last.TryGetValue(key, out var last) && now - last < _intervalMs)
        {
            return false;
        }

        _last[key] = now;
        return true;
    }

    public void Clear() => _last.Clear();
}
