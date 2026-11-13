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
/// </summary>
public sealed class Redirector : IDisposable
{
    private readonly Logger _log;
    private readonly NatTable _nat;
    private readonly BypassList _bypass;
    private readonly ushort _proxyPort;

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

    public Redirector(ProxySettings settings, BypassList bypass, NatTable nat, Logger log)
    {
        _log = log;
        _nat = nat;
        _bypass = bypass;
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
            var udpThread = new Thread(() => DropLoop(_udpHandle, isUdp: true, _cts.Token))
            {
                IsBackground = true,
                Name = "ProxyForWin.QuicBlock",
            };
            udpThread.Start();
            _threads.Add(udpThread);
        }

        if (_ipv6Handle != NativeMethods.InvalidHandleValue)
        {
            var v6Thread = new Thread(() => DropLoop(_ipv6Handle, isUdp: false, _cts.Token))
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

        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, destinationAddress);
        var ip = new IPAddress(bytes);

        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        return _bypass.MatchesIp(ip);
    }

    private void DropLoop(IntPtr handle, bool isUdp, CancellationToken ct)
    {
        var packet = new byte[NativeMethods.MaxPacketSize];

        while (!ct.IsCancellationRequested)
        {
            var address = default(WinDivertAddress);
            if (!NativeMethods.WinDivertRecv(handle, packet, (uint)packet.Length, out _, ref address))
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

            // Not resending == dropping.
            if (isUdp)
            {
                Interlocked.Increment(ref _droppedUdp);
            }
            else
            {
                Interlocked.Increment(ref _droppedIpv6);
            }
        }
    }

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
