using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using System.Xml.Linq;
using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Infrastructure.Windows;

public sealed class PowerShellSignerRuleGenerator : ISignerRuleGenerator
{
    private readonly string _scriptPath;

    public PowerShellSignerRuleGenerator(string scriptPath)
    {
        _scriptPath = Path.GetFullPath(scriptPath);
    }

    public async Task<SignerRuleGenerationResult> GenerateAsync(
        SignerRuleGenerationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!File.Exists(_scriptPath))
        {
            throw new FileNotFoundException(
                "The packaged ConfigCI signer-generation script could not be found.",
                _scriptPath);
        }

        string sourcePath = Path.GetFullPath(request.FilePath);
        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException(
                "The signer evidence file could not be found.",
                sourcePath);
        }

        string workingDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-signer-{Guid.NewGuid():N}");
        string outputPath = Path.Combine(workingDirectory, "SignerRule.xml");
        Directory.CreateDirectory(workingDirectory);

        try
        {
            ProcessStartInfo startInfo = CreateStartInfo(
                sourcePath,
                outputPath,
                request.Level,
                request.Action);
            using var process = new Process { StartInfo = startInfo };
            try
            {
                if (!process.Start())
                {
                    throw new PolicyBuildException(
                        "Windows PowerShell could not be started for signer generation.");
                }
            }
            catch (Win32Exception exception)
            {
                throw new PolicyBuildException(
                    "Windows PowerShell is unavailable, so the signer rule cannot be generated.",
                    exception);
            }

            Task<string> outputTask =
                process.StandardOutput.ReadToEndAsync(cancellationToken);
            Task<string> errorTask =
                process.StandardError.ReadToEndAsync(cancellationToken);
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
                        ? $"ConfigCI signer generation exited with code {process.ExitCode}."
                        : details);
            }

            string? jsonLine = standardOutput
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .LastOrDefault(line => line.StartsWith('{') && line.EndsWith('}'));
            if (jsonLine is null)
            {
                throw new PolicyBuildException(
                    "ConfigCI signer generation completed without returning details.");
            }

            PowerShellSignerOutput output = JsonSerializer.Deserialize<PowerShellSignerOutput>(
                    jsonLine,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new PolicyBuildException(
                    "ConfigCI returned empty signer-generation details.");
            if (!File.Exists(outputPath))
            {
                throw new PolicyBuildException(
                    "ConfigCI did not create the expected signer policy fragment.");
            }

            XDocument fragment = XDocument.Load(
                outputPath,
                LoadOptions.PreserveWhitespace);
            return new SignerRuleGenerationResult(
                request.Level,
                new PolicyRuleFragment(fragment),
                output.SignerCount,
                output.HashRuleCount,
                output.Diagnostic);
        }
        catch (JsonException exception)
        {
            throw new PolicyBuildException(
                "ConfigCI returned invalid signer-generation details.",
                exception);
        }
        finally
        {
            if (Directory.Exists(workingDirectory))
            {
                Directory.Delete(workingDirectory, recursive: true);
            }
        }
    }

    private ProcessStartInfo CreateStartInfo(
        string sourcePath,
        string outputPath,
        SignerRuleLevel level,
        PolicyRuleAction action)
    {
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
        startInfo.ArgumentList.Add("-SourcePath");
        startInfo.ArgumentList.Add(sourcePath);
        startInfo.ArgumentList.Add("-OutputPath");
        startInfo.ArgumentList.Add(outputPath);
        startInfo.ArgumentList.Add("-Level");
        startInfo.ArgumentList.Add(level.ToString());
        startInfo.ArgumentList.Add("-Action");
        startInfo.ArgumentList.Add(action.ToString());
        return startInfo;
    }

    private sealed class PowerShellSignerOutput
    {
        public int SignerCount { get; init; }

        public int HashRuleCount { get; init; }

        public string? Diagnostic { get; init; }
    }
}
