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
        IReadOnlyList<SignerRuleGenerationOutcome> outcomes =
            await GenerateBatchAsync([request], cancellationToken);
        SignerRuleGenerationOutcome outcome = outcomes[0];
        return outcome.Result
            ?? throw new PolicyBuildException(
                outcome.Error ?? "ConfigCI signer generation failed.");
    }

    public async Task<IReadOnlyList<SignerRuleGenerationOutcome>> GenerateBatchAsync(
        IReadOnlyList<SignerRuleGenerationRequest> requests,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requests);
        if (requests.Count == 0)
        {
            return [];
        }

        if (!File.Exists(_scriptPath))
        {
            throw new FileNotFoundException(
                "The packaged ConfigCI signer-generation script could not be found.",
                _scriptPath);
        }

        SignerRuleGenerationRequest[] normalizedRequests = requests
            .Select(NormalizeRequest)
            .ToArray();
        string workingDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-signer-batch-{Guid.NewGuid():N}");
        string requestPath = Path.Combine(workingDirectory, "requests.json");
        string outputDirectory = Path.Combine(workingDirectory, "results");
        Directory.CreateDirectory(outputDirectory);

        try
        {
            await File.WriteAllTextAsync(
                requestPath,
                JsonSerializer.Serialize(
                    normalizedRequests.Select(request => new PowerShellSignerRequest
                    {
                        SourcePath = request.FilePath,
                        Level = request.Level.ToString(),
                        Action = request.Action.ToString(),
                        SpecificFileNameLevel =
                            request.SpecificFileNameLevel?.ToString()
                    })),
                cancellationToken);

            ProcessStartInfo startInfo = CreateBatchStartInfo(
                requestPath,
                outputDirectory);
            using var process = new Process { StartInfo = startInfo };
            StartProcess(process);

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

            PowerShellSignerBatchOutput output = DeserializeOutput(standardOutput);
            if (output.Results.Count != normalizedRequests.Length)
            {
                throw new PolicyBuildException(
                    $"ConfigCI returned {output.Results.Count} result(s) for "
                    + $"{normalizedRequests.Length} request(s).");
            }

            var resultsByIndex = output.Results.ToDictionary(result => result.Index);
            var outcomes = new List<SignerRuleGenerationOutcome>(
                normalizedRequests.Length);
            for (int index = 0; index < normalizedRequests.Length; index++)
            {
                SignerRuleGenerationRequest request = normalizedRequests[index];
                if (!resultsByIndex.TryGetValue(index, out PowerShellSignerOutput? item))
                {
                    throw new PolicyBuildException(
                        $"ConfigCI did not return result {index}.");
                }

                if (!string.IsNullOrWhiteSpace(item.Error))
                {
                    outcomes.Add(new SignerRuleGenerationOutcome(
                        request,
                        Result: null,
                        item.Error));
                    continue;
                }

                if (string.IsNullOrWhiteSpace(item.OutputFileName))
                {
                    throw new PolicyBuildException(
                        $"ConfigCI result {index} did not identify an output policy.");
                }

                string outputPath = Path.Combine(
                    outputDirectory,
                    item.OutputFileName);
                if (!File.Exists(outputPath))
                {
                    throw new PolicyBuildException(
                        $"ConfigCI did not create result policy {index}.");
                }

                XDocument fragment = XDocument.Load(
                    outputPath,
                    LoadOptions.PreserveWhitespace);
                outcomes.Add(new SignerRuleGenerationOutcome(
                    request,
                    new SignerRuleGenerationResult(
                        request.Level,
                        new PolicyRuleFragment(fragment),
                        item.SignerCount,
                        item.HashRuleCount,
                        item.Diagnostic,
                        request.SpecificFileNameLevel,
                        item.FileAttributeCount),
                    Error: null));
            }

            return outcomes;
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

    private static SignerRuleGenerationRequest NormalizeRequest(
        SignerRuleGenerationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        string sourcePath = Path.GetFullPath(request.FilePath);
        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException(
                "The signer evidence file could not be found.",
                sourcePath);
        }

        return request with { FilePath = sourcePath };
    }

    private static void StartProcess(Process process)
    {
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
                "Windows PowerShell is unavailable, so signer rules cannot be generated.",
                exception);
        }
    }

    private static PowerShellSignerBatchOutput DeserializeOutput(
        string standardOutput)
    {
        string? jsonLine = standardOutput
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .LastOrDefault(line => line.StartsWith('{') && line.EndsWith('}'));
        if (jsonLine is null)
        {
            throw new PolicyBuildException(
                "ConfigCI signer generation completed without returning details.");
        }

        return JsonSerializer.Deserialize<PowerShellSignerBatchOutput>(
                jsonLine,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new PolicyBuildException(
                "ConfigCI returned empty signer-generation details.");
    }

    private ProcessStartInfo CreateBatchStartInfo(
        string requestPath,
        string outputDirectory)
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
        startInfo.ArgumentList.Add("-RequestPath");
        startInfo.ArgumentList.Add(requestPath);
        startInfo.ArgumentList.Add("-OutputDirectory");
        startInfo.ArgumentList.Add(outputDirectory);
        return startInfo;
    }

    private sealed class PowerShellSignerRequest
    {
        public required string SourcePath { get; init; }

        public required string Level { get; init; }

        public required string Action { get; init; }

        public string? SpecificFileNameLevel { get; init; }
    }

    private sealed class PowerShellSignerBatchOutput
    {
        public IReadOnlyList<PowerShellSignerOutput> Results { get; init; } = [];
    }

    private sealed class PowerShellSignerOutput
    {
        public int Index { get; init; }

        public string? OutputFileName { get; init; }

        public int SignerCount { get; init; }

        public int HashRuleCount { get; init; }

        public int FileAttributeCount { get; init; }

        public string? Diagnostic { get; init; }

        public string? Error { get; init; }
    }
}
