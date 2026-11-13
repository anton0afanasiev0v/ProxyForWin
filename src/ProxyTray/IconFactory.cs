using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace ProxyForWin.Tray;

internal static class IconFactory
{
    public static Icon Create(Color color, int size = 32)
    {
        using var bitmap = new Bitmap(size, size);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);

            using var brush = new SolidBrush(color);
            graphics.FillEllipse(brush, 2f, 2f, size - 4f, size - 4f);

            using var pen = new Pen(Color.FromArgb(90, 0, 0, 0), 2f);
            graphics.DrawEllipse(pen, 2f, 2f, size - 4f, size - 4f);

            using var inner = new SolidBrush(Color.FromArgb(220, Color.White));
            graphics.FillEllipse(inner, size * 0.32f, size * 0.32f, size * 0.18f, size * 0.18f);
        }

        var handle = bitmap.GetHicon();
        try
        {
            return (Icon)Icon.FromHandle(handle).Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
