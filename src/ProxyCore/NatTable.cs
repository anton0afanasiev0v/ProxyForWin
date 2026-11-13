using System.Collections.Concurrent;

namespace ProxyForWin.Core;

/// <summary>
/// Maps a redirected connection (remote address + application source port) to the
/// original destination port. The local proxy reads it to learn where the traffic
/// was actually going.
///
/// The key is (remote IPv4 address, application source port). The port is unique per
/// application socket, so two connections to the same server on different ports do
/// not collide.
/// </summary>
public sealed class NatTable
{
    private readonly ConcurrentDictionary<Key, Entry> _map = new();

    public sealed class Entry
    {
        public ushort TargetPort { get; init; }
        public long LastSeenTicks { get; set; } = Environment.TickCount64;
    }

    public readonly record struct Key(uint RemoteAddress, ushort AppPort);

    public int Count => _map.Count;

    public void Register(uint remoteAddress, ushort appPort, ushort targetPort)
    {
        _map[new Key(remoteAddress, appPort)] = new Entry { TargetPort = targetPort };
    }

    public bool TryGetTarget(uint remoteAddress, ushort appPort, out ushort targetPort)
    {
        if (_map.TryGetValue(new Key(remoteAddress, appPort), out var entry))
        {
            entry.LastSeenTicks = Environment.TickCount64;
            targetPort = entry.TargetPort;
            return true;
        }

        targetPort = 0;
        return false;
    }

    public bool Contains(uint remoteAddress, ushort appPort) => _map.ContainsKey(new Key(remoteAddress, appPort));

    public void Touch(uint remoteAddress, ushort appPort)
    {
        if (_map.TryGetValue(new Key(remoteAddress, appPort), out var entry))
        {
            entry.LastSeenTicks = Environment.TickCount64;
        }
    }

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
