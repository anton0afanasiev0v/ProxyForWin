using System.Collections.Concurrent;

namespace ProxyForWin.Core;

/// <summary>
/// Remembers the source ports of the proxy's *own* outbound sockets so that
/// WinDivert can let them through untouched.
///
/// A fixed source-port range cannot be used for this: Windows (Hyper-V, WSL,
/// Docker) may reserve it, and endpoint security software can forbid binds to it,
/// which shows up as <c>WSAEACCES</c> (10013) on <c>bind()</c>. Instead every
/// upstream/direct socket is bound to an ordinary ephemeral port and registered
/// here *before* it connects; the redirector skips packets whose source port,
/// destination address and destination port match a registered entry, so its own
/// traffic is never reflected back into the proxy (an endless loop).
///
/// The entry is removed when the tunnel is disposed. <see cref="Prune"/> is only a
/// safety net for sockets that were never disposed.
/// </summary>
public sealed class SelfConnectionRegistry
{
    private readonly ConcurrentDictionary<int, Entry> _map = new();

    public sealed class Entry
    {
        public uint DestinationAddress { get; init; }

        public ushort DestinationPort { get; init; }

        public long LastSeenTicks { get; set; } = Environment.TickCount64;
    }

    public int Count => _map.Count;

    public void Register(int localPort, uint destinationAddress, ushort destinationPort)
        => _map[localPort] = new Entry
        {
            DestinationAddress = destinationAddress,
            DestinationPort = destinationPort,
        };

    /// <summary>
    /// True when this exact flow belongs to the proxy itself. The destination is
    /// part of the key, so a stale entry cannot swallow unrelated traffic that
    /// later reuses the same local port.
    /// </summary>
    public bool Matches(int localPort, uint destinationAddress, ushort destinationPort)
    {
        if (!_map.TryGetValue(localPort, out var entry))
        {
            return false;
        }

        if (entry.DestinationAddress != destinationAddress || entry.DestinationPort != destinationPort)
        {
            return false;
        }

        entry.LastSeenTicks = Environment.TickCount64;
        return true;
    }

    public void Unregister(int localPort) => _map.TryRemove(localPort, out _);

    public int Prune(TimeSpan ttl)
    {
        var now = Environment.TickCount64;
        var removed = 0;
        foreach (var pair in _map)
        {
            if (now - pair.Value.LastSeenTicks > (long)ttl.TotalMilliseconds)
            {
                if (_map.TryRemove(pair.Key, out _))
                {
                    removed++;
                }
            }
        }

        return removed;
    }

    public void Clear() => _map.Clear();
}
