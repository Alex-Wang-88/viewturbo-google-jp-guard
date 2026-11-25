using System;
using System.Diagnostics;
using System.IO;

internal static class RunHidden
{
    private static int Main()
    {
        var basePath = AppDomain.CurrentDomain.BaseDirectory;
        var executable = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var script = Path.Combine(basePath, "Guard.ps1");
        var settings = new ProcessStartInfo(executable,
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script + "\" Run");
        settings.CreateNoWindow = true;
        settings.UseShellExecute = false;
        settings.WorkingDirectory = basePath;
        try
        {
            using (var job = new EngineJob())
            using (var process = Process.Start(settings))
            {
                try { job.Add(process); }
                catch
                {
                    if (!process.HasExited) process.Kill();
                    throw;
                }
                process.WaitForExit();
                return process.ExitCode;
            }
        }
        catch { return 1; }
    }
}
