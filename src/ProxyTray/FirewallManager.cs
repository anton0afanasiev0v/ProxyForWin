using System.Diagnostics;
using ProxyForWin.Core;

namespace ProxyForWin.Tray;

/// <summary>
/// Adds a temporary inbound firewall rule for the local proxy port while full-traffic
/// mode is active. WinDivert injects the redirected packets back into the stack, so
/// they pass through the Windows Firewall transport layers.
/// </summary>
internal static class FirewallManager
{
    private const string RuleName = "ProxyForWin redirect";

    public static void EnsureRule(int port, Logger log)
    {
        try
        {
            Run($"advfirewall firewall delete rule name=\"{RuleName}\"");
            var result = Run($"advfirewall firewall add rule name=\"{RuleName}\" dir=in action=allow " +
                             $"protocol=TCP localport={port} profile=any enable=yes");
            if (result.ExitCode == 0)
            {
                log.Info($"Правило брандмауэра добавлено для порта {port}");
            }
            else
            {
                log.Warn("Не удалось добавить правило брандмауэра: " + result.Output.Trim());
            }
        }
        catch (Exception ex)
        {
            log.Warn("Брандмауэр: " + ex.Message);
        }
    }

    public static void RemoveRule()
    {
        try
        {
            Run($"advfirewall firewall delete rule name=\"{RuleName}\"");
        }
        catch
        {
            // ignored
        }
    }

    private static (int ExitCode, string Output) Run(string arguments)
    {
        var info = new ProcessStartInfo("netsh", arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = Process.Start(info) ?? throw new InvalidOperationException("netsh не найден");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit(15000);
        return (process.HasExited ? process.ExitCode : -1, output);
    }
}
