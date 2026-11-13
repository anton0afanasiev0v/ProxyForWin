using ProxyForWin.Core;

namespace ProxyForWin.Tray;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        using var mutex = new Mutex(initiallyOwned: true, @"Global\ProxyForWin.SingleInstance", out var created);
        if (!created)
        {
            MessageBox.Show(
                "ProxyForWin уже запущен. Найдите иконку в области уведомлений.",
                "ProxyForWin",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        AppDomain.CurrentDomain.ProcessExit += (_, _) => RestoreOnExit();

        Application.ThreadException += (_, e) =>
        {
            RestoreOnExit();
            MessageBox.Show(
                "Непредвиденная ошибка: " + e.Exception.Message,
                "ProxyForWin",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        };

        AppDomain.CurrentDomain.UnhandledException += (_, _) => RestoreOnExit();

        Application.Run(new TrayAppContext());
    }

    /// <summary>Last-resort restore of the system proxy settings.</summary>
    private static void RestoreOnExit()
    {
        try
        {
            var dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "ProxyForWin");
            var logger = new Logger(Path.Combine(dataDir, "proxy.log"));
            var manager = new SystemProxyManager(Path.Combine(dataDir, "state.json"), logger);
            manager.Restore();
        }
        catch
        {
            // ignored
        }
    }
}
