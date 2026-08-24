using System.Diagnostics;

namespace PKaido;

internal sealed record CliResult(int ExitCode, string StdOut, string StdErr, TimeSpan Elapsed);

internal static class CliRunner
{
    public static CliResult Run(string cliPath, IReadOnlyList<string> args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = cliPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        var stopwatch = Stopwatch.StartNew();

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start '{cliPath}'.");

        string stdOut = process.StandardOutput.ReadToEnd();
        string stdErr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        stopwatch.Stop();

        return new CliResult(process.ExitCode, stdOut.Trim(), stdErr.Trim(), stopwatch.Elapsed);
    }
}
