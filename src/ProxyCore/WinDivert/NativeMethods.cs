using System.Runtime.InteropServices;

namespace ProxyForWin.Core.WinDivert;

/// <summary>P/Invoke for WinDivert 2.2 (WinDivert.dll + WinDivert64.sys).</summary>
internal static class NativeMethods
{
    public const int LayerNetwork = 0;
    public const short DefaultPriority = 0;
    public const ulong FlagSniff = 0x0001;
    public const ulong FlagDrop = 0x0002;

    public const int ShutdownReceive = 1;
    public const int ShutdownSend = 2;
    public const int ShutdownBoth = ShutdownReceive | ShutdownSend;

    public static readonly IntPtr InvalidHandleValue = new(-1);

    /// <summary>WINDIVERT_MTU_MAX + IPv6 header headroom.</summary>
    public const int MaxPacketSize = 40 + 0xFFFF + 64;

    [DllImport("WinDivert.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] packet,
        uint packetLen,
        out uint recvLen,
        ref WinDivertAddress address);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(
        IntPtr handle,
        byte[] packet,
        uint packetLen,
        out uint sendLen,
        ref WinDivertAddress address);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertShutdown(IntPtr handle, int how);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCalcChecksums(
        byte[] packet,
        uint packetLen,
        ref WinDivertAddress address,
        ulong flags);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperParsePacket(
        byte[] packet,
        uint packetLen,
        out IntPtr ipHeader,
        out IntPtr ipv6Header,
        out IntPtr icmpHeader,
        out IntPtr icmpv6Header,
        out IntPtr tcpHeader,
        out IntPtr udpHeader,
        out IntPtr payload,
        out uint payloadLength,
        out uint flags);
}

/// <summary>
/// Layout of WINDIVERT_ADDRESS (80 bytes). The flags are a UINT32 bitfield:
/// Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1,
/// IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct WinDivertAddress
{
    private const uint OutboundBit = 1u << 17;
    private const uint LoopbackBit = 1u << 18;
    private const uint ImpostorBit = 1u << 19;
    private const uint Ipv6Bit = 1u << 20;

    [FieldOffset(0)]
    public long Timestamp;

    [FieldOffset(8)]
    private uint _flags;

    [FieldOffset(16)]
    public uint IfIdx;

    [FieldOffset(20)]
    public uint SubIfIdx;

    public bool Outbound
    {
        get => Get(OutboundBit);
        set => Set(OutboundBit, value);
    }

    public bool Loopback
    {
        get => Get(LoopbackBit);
        set => Set(LoopbackBit, value);
    }

    public bool Impostor
    {
        get => Get(ImpostorBit);
        set => Set(ImpostorBit, value);
    }

    public bool IsIpv6
    {
        get => Get(Ipv6Bit);
        set => Set(Ipv6Bit, value);
    }

    private bool Get(uint bit) => (_flags & bit) != 0;

    private void Set(uint bit, bool value)
    {
        if (value)
        {
            _flags |= bit;
        }
        else
        {
            _flags &= ~bit;
        }
    }
}
