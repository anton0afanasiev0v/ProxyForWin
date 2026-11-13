using System.Buffers.Binary;

namespace ProxyForWin.Core;

/// <summary>
/// Minimal, allocation-free TCP/IPv4 packet access for the WinDivert redirector.
///
/// The redirector works the same way as the WinDivert "streamdump" sample:
/// an outbound packet from an application is rewritten into an inbound packet that
/// arrives at the local proxy, and the proxy's replies are rewritten back so that
/// the application believes it is talking to the real server.
/// </summary>
public sealed class PacketRewriter
{
    public readonly record struct TcpInfo(
        int IpOffset,
        int IpHeaderLength,
        int TcpOffset,
        uint SrcAddress,
        uint DstAddress,
        ushort SrcPort,
        ushort DstPort);

    /// <summary>Parses an IPv4 TCP packet. Returns false for anything else.</summary>
    public static bool TryParseIpv4Tcp(ReadOnlySpan<byte> packet, out TcpInfo info)
    {
        info = default;
        if (packet.Length < 20)
        {
            return false;
        }

        var version = packet[0] >> 4;
        if (version != 4)
        {
            return false;
        }

        var ipHeaderLength = (packet[0] & 0x0F) * 4;
        if (ipHeaderLength < 20 || packet.Length < ipHeaderLength + 20)
        {
            return false;
        }

        if (packet[9] != 6)
        {
            return false;
        }

        var fragmentOffset = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
        var moreFragments = (fragmentOffset & 0x2000) != 0;
        var offset = fragmentOffset & 0x1FFF;
        if (moreFragments || offset != 0)
        {
            // Fragmented TCP is not handled; leave it untouched.
            return false;
        }

        var tcpOffset = ipHeaderLength;
        var srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(tcpOffset, 2));
        var dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(tcpOffset + 2, 2));
        var srcAddress = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4));
        var dstAddress = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4));

        info = new TcpInfo(0, ipHeaderLength, tcpOffset, srcAddress, dstAddress, srcPort, dstPort);
        return true;
    }

    /// <summary>
    /// Application -> real server becomes: "server:appPort -> localIp:proxyPort",
    /// injected as inbound. The local proxy sees the application's source port and
    /// the server address, which is enough to find the original destination port.
    /// </summary>
    public static void RewriteAppToProxy(Span<byte> packet, in TcpInfo info, ushort proxyPort)
    {
        BinaryPrimitives.WriteUInt32BigEndian(packet.Slice(info.IpOffset + 12, 4), info.DstAddress);
        BinaryPrimitives.WriteUInt32BigEndian(packet.Slice(info.IpOffset + 16, 4), info.SrcAddress);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(info.TcpOffset + 2, 2), proxyPort);
        // Source port is preserved on purpose.
    }

    /// <summary>
    /// Proxy reply -> application becomes: "server:targetPort -> localIp:appPort",
    /// injected as inbound. The source port is restored to the original destination
    /// port so the application accepts the packet.
    /// </summary>
    public static void RewriteProxyToApp(Span<byte> packet, in TcpInfo info, ushort targetPort)
    {
        BinaryPrimitives.WriteUInt32BigEndian(packet.Slice(info.IpOffset + 12, 4), info.DstAddress);
        BinaryPrimitives.WriteUInt32BigEndian(packet.Slice(info.IpOffset + 16, 4), info.SrcAddress);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(info.TcpOffset, 2), targetPort);
        // Destination port (application port) is preserved.
    }

    public static uint ReadAddress(ReadOnlySpan<byte> packet)
        => BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4));

    public static ushort ReadSourcePort(ReadOnlySpan<byte> packet, int ipHeaderLength)
        => BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHeaderLength, 2));

    public static ushort ReadDestinationPort(ReadOnlySpan<byte> packet, int ipHeaderLength)
        => BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHeaderLength + 2, 2));
}
