using System.Diagnostics;
using ProxyForWin.Core;

namespace ProxyForWin.Tray;

/// <summary>Autostart through Task Scheduler (needed because the app requires admin).</summary>
public static class AutostartManager
{
    private const string TaskName = "ProxyForWin";

    public static bool IsEnabled()
    {
        try
        {
            var result = Run("schtasks", $"/Query /TN \"{TaskName}\"");
            return result.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static void Enable(string? exePath = null)
    {
        exePath ??= Environment.ProcessPath ?? throw new InvalidOperationException("Не удалось определить путь к программе");
        var result = Run("schtasks",
            $"/Create /SC ONLOGON /RL HIGHEST /F /TN \"{TaskName}\" /TR \"\\\"{exePath}\\\" --minimized\"");
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException("Не удалось включить автозапуск: " + result.Output);
        }
    }

    public static void Disable()
    {
        var result = Run("schtasks", $"/Delete /TN \"{TaskName}\" /F");
        if (result.ExitCode != 0 && !result.Output.Contains("не найдена", StringComparison.OrdinalIgnoreCase) &&
            !result.Output.Contains("cannot find", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Не удалось выключить автозапуск: " + result.Output);
        }
    }

    private static (int ExitCode, string Output) Run(string file, string arguments)
    {
        var info = new ProcessStartInfo(file, arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = Process.Start(info) ?? throw new InvalidOperationException("Не удалось запустить " + file);
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit(15000);
        return (process.HasExited ? process.ExitCode : -1, output);
    }
}
