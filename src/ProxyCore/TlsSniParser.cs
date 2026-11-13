using System.Buffers.Binary;

namespace ProxyForWin.Core;

/// <summary>Extracts the SNI host name from a TLS ClientHello.</summary>
public static class TlsSniParser
{
    public static string? TryGetServerName(ReadOnlySpan<byte> data)
    {
        try
        {
            return Parse(data);
        }
        catch
        {
            return null;
        }
    }

    private static string? Parse(ReadOnlySpan<byte> data)
    {
        // TLS record: type(1) version(2) length(2)
        if (data.Length < 5 || data[0] != 0x16)
        {
            return null;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(3, 2));
        if (recordLength == 0 || data.Length < 5 + recordLength)
        {
            return null;
        }

        var handshake = data.Slice(5, recordLength);
        if (handshake.Length < 4 || handshake[0] != 0x01)
        {
            return null;
        }

        var handshakeLength = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
        if (handshake.Length < 4 + handshakeLength)
        {
            return null;
        }

        var p = 4;
        // client_version
        p += 2;
        // random
        p += 32;
        if (p >= handshake.Length)
        {
            return null;
        }

        // session_id
        var sessionIdLength = handshake[p];
        p += 1 + sessionIdLength;

        if (p + 2 > handshake.Length)
        {
            return null;
        }

        // cipher_suites
        var cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(handshake.Slice(p, 2));
        p += 2 + cipherSuitesLength;

        if (p >= handshake.Length)
        {
            return null;
        }

        // compression_methods
        var compressionLength = handshake[p];
        p += 1 + compressionLength;

        if (p + 2 > handshake.Length)
        {
            return null;
        }

        // extensions
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(handshake.Slice(p, 2));
        p += 2;
        var extensionsEnd = Math.Min(handshake.Length, p + extensionsLength);

        while (p + 4 <= extensionsEnd)
        {
            var extensionType = BinaryPrimitives.ReadUInt16BigEndian(handshake.Slice(p, 2));
            var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(handshake.Slice(p + 2, 2));
            p += 4;

            if (p + extensionLength > extensionsEnd)
            {
                return null;
            }

            if (extensionType == 0x0000)
            {
                var names = handshake.Slice(p, extensionLength);
                if (names.Length < 2)
                {
                    return null;
                }

                var listLength = BinaryPrimitives.ReadUInt16BigEndian(names.Slice(0, 2));
                var q = 2;
                var listEnd = Math.Min(names.Length, 2 + listLength);
                while (q + 3 <= listEnd)
                {
                    var nameType = names[q];
                    var nameLength = BinaryPrimitives.ReadUInt16BigEndian(names.Slice(q + 1, 2));
                    q += 3;
                    if (nameType == 0 && q + nameLength <= listEnd)
                    {
                        return System.Text.Encoding.ASCII.GetString(names.Slice(q, nameLength));
                    }

                    q += nameLength;
                }
            }

            p += extensionLength;
        }

        return null;
    }
}
