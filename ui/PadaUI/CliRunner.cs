using System.Diagnostics;

namespace PadaUI;

internal sealed record CliResult(int ExitCode, string StdOut, string StdErr);

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

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start '{cliPath}'.");

        string stdOut = process.StandardOutput.ReadToEnd();
        string stdErr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return new CliResult(process.ExitCode, stdOut.Trim(), stdErr.Trim());
    }
}
