using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace ProxyForWin.Core.WinDivert;

/// <summary>
/// Reflects outbound TCP connections into the local proxy and rewrites the proxy's
/// replies back, so applications that ignore Windows proxy settings still work.
///
/// Technique (same as the WinDivert "streamdump" sample):
///   app L:la -> R:rp        becomes inbound  R:la -> L:proxyPort   (proxy sees R:la)
///   proxy L:proxyPort -> R:la becomes inbound R:rp -> L:la        (app sees R:rp)
/// Correct source/destination ports are preserved; only the addresses and the
/// destination/source ports are swapped, so TCP sequence numbers stay valid.
///
/// The UDP/443 (QUIC) and IPv6 blockers let packets through when the destination is
/// in the bypass list or in the VPN endpoint list. That is required for VPN clients
/// (AmneziaWG often runs on UDP/443) and for IPv6-only VPN servers.
/// </summary>
public sealed class Redirector : IDisposable
{
    private readonly Logger _log;
    private readonly NatTable _nat;
    private readonly BypassList _bypass;
    private readonly BypassList _vpn;
    private readonly ushort _proxyPort;
    private readonly LogThrottle _blockThrottle = new(TimeSpan.FromSeconds(30));

    private readonly IntPtr _tcpHandle = NativeMethods.InvalidHandleValue;
    private readonly IntPtr _udpHandle = NativeMethods.InvalidHandleValue;
    private readonly IntPtr _ipv6Handle = NativeMethods.InvalidHandleValue;

    private readonly List<IntPtr> _handles = new();
    private readonly List<Thread> _threads = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly object _stateLock = new();
    private Timer? _pruneTimer;

    private volatile bool _running;
    private long _redirected;
    private long _droppedUdp;
    private long _droppedIpv6;
    private long _passedVpn;

    public Redirector(ProxySettings settings, BypassList bypass, BypassList vpn, NatTable nat, Logger log)
    {
        _log = log;
        _nat = nat;
        _bypass = bypass;
        _vpn = vpn;
        _proxyPort = (ushort)settings.ListenPort;

        try
        {
            var filter = BuildTcpFilter((ushort)settings.ListenPort);
            _tcpHandle = Open(filter, "TCP-перехват");
            _handles.Add(_tcpHandle);

            if (settings.BlockQuic)
            {
                _udpHandle = Open("outbound and udp and udp.DstPort == 443 and not loopback and not impostor", "блокировка QUIC");
                _handles.Add(_udpHandle);
            }

            if (settings.BlockIpv6)
            {
                _ipv6Handle = Open("outbound and ipv6 and (tcp or udp) and not loopback and not impostor", "блокировка IPv6");
                _handles.Add(_ipv6Handle);
            }
        }
        catch
        {
            foreach (var handle in _handles)
            {
                if (handle != NativeMethods.InvalidHandleValue)
                {
                    NativeMethods.WinDivertClose(handle);
                }
            }

            _handles.Clear();
            throw;
        }
    }

    public bool IsRunning => _running;

    public long RedirectedConnections => Interlocked.Read(ref _redirected);

    public long DroppedQuic => Interlocked.Read(ref _droppedUdp);

    public long DroppedIpv6 => Interlocked.Read(ref _droppedIpv6);

    /// <summary>UDP/IPv6 packets that were allowed through because of the bypass/VPN lists.</summary>
    public long PassedVpnPackets => Interlocked.Read(ref _passedVpn);

    private IntPtr Open(string filter, string what)
    {
        var handle = NativeMethods.WinDivertOpen(filter, NativeMethods.LayerNetwork, NativeMethods.DefaultPriority, 0);
        if (handle == NativeMethods.InvalidHandleValue)
        {
            var error = Marshal.GetLastWin32Error();
            throw new WinDivertException($"Не удалось открыть WinDivert ({what}), код {error}. " +
                                         "Нужны права администратора и файлы WinDivert.dll/WinDivert64.sys рядом с программой.");
        }

        return handle;
    }

    public void Start()
    {
        lock (_stateLock)
        {
            if (_running)
            {
                return;
            }

            _running = true;
        }

        var tcpThread = new Thread(() => TcpLoop(_tcpHandle, _cts.Token))
        {
            IsBackground = true,
            Name = "ProxyForWin.TcpRedirect",
        };
        tcpThread.Start();
        _threads.Add(tcpThread);

        if (_udpHandle != NativeMethods.InvalidHandleValue)
        {
            var udpThread = new Thread(() => BlockLoop(_udpHandle, isUdp: true, _cts.Token))
            {
                IsBackground = true,
                Name = "ProxyForWin.QuicBlock",
            };
            udpThread.Start();
            _threads.Add(udpThread);
        }

        if (_ipv6Handle != NativeMethods.InvalidHandleValue)
        {
            var v6Thread = new Thread(() => BlockLoop(_ipv6Handle, isUdp: false, _cts.Token))
            {
                IsBackground = true,
                Name = "ProxyForWin.Ipv6Block",
            };
            v6Thread.Start();
            _threads.Add(v6Thread);
        }

        _log.Info("Перехват трафика включён (WinDivert)");
        _pruneTimer = new Timer(_ => _nat.Prune(TimeSpan.FromMinutes(10)), null, 30_000, 30_000);
    }

    public void Stop()
    {
        List<IntPtr> handles;
        lock (_stateLock)
        {
            if (!_running && _handles.Count == 0)
            {
                return;
            }

            _running = false;
            handles = _handles.ToList();
            _handles.Clear();
        }

        _cts.Cancel();

        _pruneTimer?.Dispose();
        _pruneTimer = null;

        foreach (var handle in handles)
        {
            if (handle != NativeMethods.InvalidHandleValue)
            {
                NativeMethods.WinDivertShutdown(handle, NativeMethods.ShutdownBoth);
            }
        }

        foreach (var thread in _threads)
        {
            try
            {
                thread.Join(TimeSpan.FromSeconds(3));
            }
            catch
            {
                // ignored
            }
        }

        _threads.Clear();

        foreach (var handle in handles)
        {
            if (handle != NativeMethods.InvalidHandleValue)
            {
                NativeMethods.WinDivertClose(handle);
            }
        }

        _nat.Clear();
        _log.Info("Перехват трафика выключен");
    }

    private void TcpLoop(IntPtr handle, CancellationToken ct)
    {
        var packet = new byte[NativeMethods.MaxPacketSize];

        while (!ct.IsCancellationRequested)
        {
            var address = default(WinDivertAddress);
            if (!NativeMethods.WinDivertRecv(handle, packet, (uint)packet.Length, out var length, ref address))
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                var error = Marshal.GetLastWin32Error();
                if (error == 0x6) // ERROR_INVALID_HANDLE
                {
                    break;
                }

                Thread.Sleep(1);
                continue;
            }

            try
            {
                HandleTcpPacket(packet, (int)length, ref address, handle);
            }
            catch (Exception ex)
            {
                _log.Debug("Ошибка перехвата пакета: " + ex.Message);
                NativeMethods.WinDivertSend(handle, packet, length, out _, ref address);
            }
        }
    }

    private void HandleTcpPacket(byte[] packet, int length, ref WinDivertAddress address, IntPtr handle)
    {
        var span = packet.AsSpan(0, length);
        if (!PacketRewriter.TryParseIpv4Tcp(span, out var info))
        {
            NativeMethods.WinDivertSend(handle, packet, (uint)length, out _, ref address);
            return;
        }

        var sourceIsProxy = info.SrcPort == _proxyPort;
        var destinationIsProxy = info.DstPort == _proxyPort;

        if (address.Outbound)
        {
            if (!sourceIsProxy && !destinationIsProxy)
            {
                if (IsExcluded(info.DstAddress, info.DstPort))
                {
                    NativeMethods.WinDivertSend(handle, packet, (uint)length, out _, ref address);
                    return;
                }

                // Remember where the application really wanted to go and reflect
                // the packet into the local proxy.
                _nat.Register(info.DstAddress, info.SrcPort, info.DstPort);
                if (IsNewConnection(span))
                {
                    Interlocked.Increment(ref _redirected);
                    if (!_log.Verbose && IsNewConnectionToVpn(info.DstAddress))
                    {
                        _log.Info($"VPN-сервер {FormatIp(info.DstAddress)}:{info.DstPort} — TCP заворачивается в прокси");
                    }
                }

                PacketRewriter.RewriteAppToProxy(span, info, _proxyPort);
                address.Outbound = false;
                address.Impostor = true;
            }
            else if (sourceIsProxy)
            {
                // Reply from the local proxy: restore the original server address
                // and port so the application accepts the packet.
                if (!_nat.TryGetTarget(info.DstAddress, info.DstPort, out var targetPort))
                {
                    // Stale connection: drop instead of leaking the proxy endpoint.
                    return;
                }

                PacketRewriter.RewriteProxyToApp(span, info, targetPort);
                address.Outbound = false;
                address.Impostor = true;
            }
            else
            {
                NativeMethods.WinDivertSend(handle, packet, (uint)length, out _, ref address);
                return;
            }
        }

        NativeMethods.WinDivertHelperCalcChecksums(packet, (uint)length, ref address, 0);
        NativeMethods.WinDivertSend(handle, packet, (uint)length, out _, ref address);
    }

    private static bool IsNewConnection(ReadOnlySpan<byte> packet)
    {
        if (!PacketRewriter.TryParseIpv4Tcp(packet, out var info))
        {
            return false;
        }

        var flags = packet[info.TcpOffset + 13];
        var syn = (flags & 0x02) != 0;
        var ack = (flags & 0x10) != 0;
        return syn && !ack;
    }

    private bool IsExcluded(uint destinationAddress, ushort destinationPort)
    {
        if (destinationPort == _proxyPort)
        {
            return true;
        }

        var ip = ToIp(destinationAddress);

        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        return _bypass.MatchesIp(ip);
    }

    /// <summary>
    /// UDP/443 and IPv6 blockers: the bypass and VPN lists are allowed through,
    /// everything else is dropped so applications fall back to TCP.
    /// </summary>
    private void BlockLoop(IntPtr handle, bool isUdp, CancellationToken ct)
    {
        var packet = new byte[NativeMethods.MaxPacketSize];

        while (!ct.IsCancellationRequested)
        {
            var address = default(WinDivertAddress);
            if (!NativeMethods.WinDivertRecv(handle, packet, (uint)packet.Length, out var length, ref address))
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                var error = Marshal.GetLastWin32Error();
                if (error == 0x6)
                {
                    break;
                }

                Thread.Sleep(1);
                continue;
            }

            if (TryGetDestination(packet.AsSpan(0, (int)length), out var destination, out var port) &&
                IsExemptFromBlocking(destination))
            {
                Interlocked.Increment(ref _passedVpn);
                address.Impostor = true;
                NativeMethods.WinDivertSend(handle, packet, length, out _, ref address);
                continue;
            }

            if (isUdp)
            {
                Interlocked.Increment(ref _droppedUdp);
                if (destination is not null && _blockThrottle.ShouldLog("udp:" + destination))
                {
                    _log.Info($"Заблокирован UDP/{port} → {destination}. " +
                              "Если это VPN-сервер, добавьте его адрес в «VPN-серверы».");
                }
            }
            else
            {
                Interlocked.Increment(ref _droppedIpv6);
                if (destination is not null && _blockThrottle.ShouldLog("v6:" + destination))
                {
                    _log.Info($"Заблокирован IPv6 → {destination}. " +
                              "Если это VPN-сервер, добавьте его адрес в «VPN-серверы».");
                }
            }
        }
    }

    private bool IsExemptFromBlocking(IPAddress? address)
    {
        if (address is null)
        {
            return false;
        }

        return _bypass.MatchesIp(address) || _vpn.MatchesIp(address);
    }

    private static bool TryGetDestination(ReadOnlySpan<byte> packet, out IPAddress? destination, out ushort port)
    {
        destination = null;
        port = 0;

        if (packet.Length < 20)
        {
            return false;
        }

        var version = packet[0] >> 4;
        if (version == 4)
        {
            var headerLength = (packet[0] & 0x0F) * 4;
            if (headerLength < 20 || packet.Length < headerLength + 4)
            {
                return false;
            }

            destination = new IPAddress(packet.Slice(16, 4));
            port = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(headerLength + 2, 2));
            return true;
        }

        if (version == 6)
        {
            // IPv6 header: 40 bytes, then TCP/UDP header (ports at +0 and +2).
            if (packet.Length < 44)
            {
                return false;
            }

            destination = new IPAddress(packet.Slice(24, 16));
            port = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(42, 2));
            return true;
        }

        return false;
    }

    private static IPAddress ToIp(uint address)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, address);
        return new IPAddress(bytes);
    }

    private static string FormatIp(uint address) => ToIp(address).ToString();

    private bool IsNewConnectionToVpn(uint destinationAddress) => _vpn.MatchesIp(ToIp(destinationAddress));

    private static string BuildTcpFilter(ushort proxyPort)
        => "outbound and tcp and not loopback and not impostor and " +
           $"tcp.DstPort != {proxyPort} and " +
           $"(tcp.SrcPort < {UpstreamConnector.BindPortMin} or tcp.SrcPort > {UpstreamConnector.BindPortMax}) and " +
           $"(tcp.DstPort < {UpstreamConnector.BindPortMin} or tcp.DstPort > {UpstreamConnector.BindPortMax})";

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}

public sealed class WinDivertException : Exception
{
    public WinDivertException(string message)
        : base(message)
    {
    }
}
