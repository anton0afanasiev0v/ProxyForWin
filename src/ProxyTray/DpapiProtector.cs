using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ProxyForWin.Core;

namespace ProxyForWin.Tray;

/// <summary>Protects the proxy password with DPAPI (current Windows user).</summary>
public sealed class DpapiProtector : ISecretProtector
{
    private const int CryptProtectUiForbidden = 0x1;

    public string Protect(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
        {
            return string.Empty;
        }

        var data = Encoding.UTF8.GetBytes(plainText);
        var protectedBytes = Protect(data, CryptProtectUiForbidden);
        return "dpapi:" + Convert.ToBase64String(protectedBytes);
    }

    public string Unprotect(string protectedText)
    {
        if (string.IsNullOrEmpty(protectedText))
        {
            return string.Empty;
        }

        if (!protectedText.StartsWith("dpapi:", StringComparison.Ordinal))
        {
            return protectedText;
        }

        var bytes = Convert.FromBase64String(protectedText[6..]);
        var plain = Unprotect(bytes, CryptProtectUiForbidden);
        return Encoding.UTF8.GetString(plain);
    }

    private static byte[] Protect(byte[] data, int flags)
    {
        var input = new DataBlob();
        var output = new DataBlob();

        try
        {
            input.Data = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, input.Data, data.Length);
            input.Size = data.Length;

            if (!CryptProtectData(ref input, "ProxyForWin", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, flags, ref output))
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            var result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, output.Size);
            return result;
        }
        finally
        {
            if (input.Data != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(input.Data);
            }

            if (output.Data != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(output.Data);
            }
        }
    }

    private static byte[] Unprotect(byte[] data, int flags)
    {
        var input = new DataBlob();
        var output = new DataBlob();

        try
        {
            input.Data = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, input.Data, data.Length);
            input.Size = data.Length;

            if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, flags, ref output))
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            var result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, output.Size);
            return result;
        }
        finally
        {
            if (input.Data != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(input.Data);
            }

            if (output.Data != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(output.Data);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn,
        string? description,
        IntPtr entropy,
        IntPtr reserved,
        IntPtr promptStruct,
        int flags,
        ref DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn,
        IntPtr description,
        IntPtr entropy,
        IntPtr reserved,
        IntPtr promptStruct,
        int flags,
        ref DataBlob dataOut);
}
