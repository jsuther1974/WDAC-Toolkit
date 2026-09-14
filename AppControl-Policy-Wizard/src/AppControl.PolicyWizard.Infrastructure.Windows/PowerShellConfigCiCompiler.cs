using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Infrastructure.Windows;

public sealed class PowerShellConfigCiCompiler : IPolicyCompiler
{
    private readonly string _scriptPath;

    public PowerShellConfigCiCompiler(string scriptPath)
    {
        _scriptPath = Path.GetFullPath(scriptPath);
    }

    public async Task<PolicyCompileResult> CompileAsync(
        PolicyCompileRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_scriptPath))
        {
            throw new FileNotFoundException(
                "The packaged ConfigCI build script could not be found.",
                _scriptPath);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(_scriptPath);
        startInfo.ArgumentList.Add("-XmlPath");
        startInfo.ArgumentList.Add(request.XmlPath);
        startInfo.ArgumentList.Add("-PolicyName");
        startInfo.ArgumentList.Add(request.PolicyName);
        startInfo.ArgumentList.Add("-Version");
        startInfo.ArgumentList.Add(request.Version);

        if (request.ResetPolicyIdentity)
        {
            startInfo.ArgumentList.Add("-ResetPolicyIdentity");
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                throw new PolicyBuildException("Windows PowerShell could not be started.");
            }
        }
        catch (Win32Exception exception)
        {
            throw new PolicyBuildException(
                "Windows PowerShell is unavailable, so the policy cannot be compiled.",
                exception);
        }

        Task<string> outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None);
            }

            throw;
        }

        string standardOutput = await outputTask;
        string standardError = await errorTask;

        if (process.ExitCode != 0)
        {
            string details = string.IsNullOrWhiteSpace(standardError)
                ? standardOutput.Trim()
                : standardError.Trim();
            throw new PolicyBuildException(
                string.IsNullOrWhiteSpace(details)
                    ? $"ConfigCI exited with code {process.ExitCode}."
                    : details);
        }

        string? jsonLine = standardOutput
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .LastOrDefault(line => line.StartsWith('{') && line.EndsWith('}'));

        if (jsonLine is null)
        {
            throw new PolicyBuildException(
                "ConfigCI completed without returning policy build details.");
        }

        try
        {
            PowerShellBuildOutput output = JsonSerializer.Deserialize<PowerShellBuildOutput>(
                    jsonLine,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new PolicyBuildException(
                    "ConfigCI returned empty policy build details.");

            return new PolicyCompileResult(
                output.PolicyID,
                output.BasePolicyID,
                output.Version
                    ?? throw new PolicyBuildException(
                        "ConfigCI did not return the policy version."),
                output.BinaryPath
                    ?? throw new PolicyBuildException(
                        "ConfigCI did not return a binary policy path."));
        }
        catch (JsonException exception)
        {
            throw new PolicyBuildException(
                "ConfigCI returned invalid policy build details.",
                exception);
        }
    }

    private sealed class PowerShellBuildOutput
    {
        public string? PolicyID { get; init; }

        public string? BasePolicyID { get; init; }

        public string? Version { get; init; }

        public string? BinaryPath { get; init; }
    }
}
