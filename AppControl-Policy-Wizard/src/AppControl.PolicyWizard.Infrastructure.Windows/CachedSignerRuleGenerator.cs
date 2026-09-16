using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Infrastructure.Windows;

public sealed class CachedSignerRuleGenerator : ISignerRuleGenerator
{
    private readonly ISignerRuleGenerator _inner;
    private readonly string _cacheDirectory;
    private readonly string _versionToken;

    public CachedSignerRuleGenerator(
        ISignerRuleGenerator inner,
        string cacheDirectory,
        string versionToken)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _cacheDirectory = Path.GetFullPath(cacheDirectory);
        _versionToken = string.IsNullOrWhiteSpace(versionToken)
            ? throw new ArgumentException(
                "A cache version token is required.",
                nameof(versionToken))
            : versionToken;
    }

    public async Task<SignerRuleGenerationResult> GenerateAsync(
        SignerRuleGenerationRequest request,
        CancellationToken cancellationToken = default)
    {
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

        Directory.CreateDirectory(_cacheDirectory);
        var fileHashes = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase);
        var keys = new string[requests.Count];
        var outcomes = new SignerRuleGenerationOutcome?[requests.Count];
        var misses = new Dictionary<string, CacheMiss>(StringComparer.Ordinal);

        for (int index = 0; index < requests.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SignerRuleGenerationRequest request = NormalizeRequest(requests[index]);
            if (!fileHashes.TryGetValue(request.FilePath, out string? fileHash))
            {
                fileHash = await ComputeFileHashAsync(
                    request.FilePath,
                    cancellationToken);
                fileHashes.Add(request.FilePath, fileHash);
            }

            string key = ComputeCacheKey(request, fileHash);
            keys[index] = key;
            SignerRuleGenerationResult? cached = await TryReadAsync(
                key,
                request,
                cancellationToken);
            if (cached is not null)
            {
                outcomes[index] = new SignerRuleGenerationOutcome(
                    request,
                    cached,
                    Error: null);
                continue;
            }

            if (!misses.TryGetValue(key, out CacheMiss? miss))
            {
                miss = new CacheMiss(request);
                misses.Add(key, miss);
            }

            miss.Indices.Add(index);
        }

        if (misses.Count > 0)
        {
            CacheMiss[] pending = misses.Values.ToArray();
            IReadOnlyList<SignerRuleGenerationOutcome> generated =
                await _inner.GenerateBatchAsync(
                    pending.Select(miss => miss.Request).ToArray(),
                    cancellationToken);
            if (generated.Count != pending.Length)
            {
                throw new PolicyBuildException(
                    $"The signer generator returned {generated.Count} result(s) "
                    + $"for {pending.Length} cache miss(es).");
            }

            for (int pendingIndex = 0;
                pendingIndex < pending.Length;
                pendingIndex++)
            {
                CacheMiss miss = pending[pendingIndex];
                SignerRuleGenerationOutcome generatedOutcome =
                    generated[pendingIndex];
                SignerRuleGenerationOutcome normalizedOutcome =
                    generatedOutcome with { Request = miss.Request };
                if (normalizedOutcome.Result is not null
                    && normalizedOutcome.Error is null)
                {
                    string key = keys[miss.Indices[0]];
                    await WriteAsync(
                        key,
                        normalizedOutcome.Result,
                        cancellationToken);
                }

                foreach (int index in miss.Indices)
                {
                    outcomes[index] = normalizedOutcome with
                    {
                        Request = NormalizeRequest(requests[index])
                    };
                }
            }
        }

        return outcomes
            .Select((outcome, index) =>
                outcome
                ?? throw new PolicyBuildException(
                    $"Signer generation did not produce outcome {index}."))
            .ToArray();
    }

    private async Task<SignerRuleGenerationResult?> TryReadAsync(
        string key,
        SignerRuleGenerationRequest request,
        CancellationToken cancellationToken)
    {
        string cachePath = GetCachePath(key);
        if (!File.Exists(cachePath))
        {
            return null;
        }

        try
        {
            string json = await File.ReadAllTextAsync(
                cachePath,
                cancellationToken);
            CacheEntry entry = JsonSerializer.Deserialize<CacheEntry>(json)
                ?? throw new InvalidDataException(
                    $"Signer cache entry '{cachePath}' is empty.");
            if (!string.Equals(
                    entry.VersionToken,
                    _versionToken,
                    StringComparison.Ordinal))
            {
                return null;
            }

            XDocument fragment = XDocument.Parse(
                entry.PolicyXml,
                LoadOptions.PreserveWhitespace);
            return new SignerRuleGenerationResult(
                request.Level,
                new PolicyRuleFragment(fragment),
                entry.SignerCount,
                entry.HashRuleCount,
                entry.Diagnostic,
                request.SpecificFileNameLevel,
                entry.FileAttributeCount);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Signer cache entry '{cachePath}' contains invalid JSON.",
                exception);
        }
        catch (System.Xml.XmlException exception)
        {
            throw new InvalidDataException(
                $"Signer cache entry '{cachePath}' contains invalid policy XML.",
                exception);
        }
    }

    private async Task WriteAsync(
        string key,
        SignerRuleGenerationResult result,
        CancellationToken cancellationToken)
    {
        string cachePath = GetCachePath(key);
        string temporaryPath = $"{cachePath}.{Guid.NewGuid():N}.tmp";
        var entry = new CacheEntry
        {
            VersionToken = _versionToken,
            SignerCount = result.SignerCount,
            HashRuleCount = result.HashRuleCount,
            FileAttributeCount = result.FileAttributeCount,
            Diagnostic = result.Diagnostic,
            PolicyXml = result.Fragment.Document.ToString(
                SaveOptions.DisableFormatting)
        };

        try
        {
            await File.WriteAllTextAsync(
                temporaryPath,
                JsonSerializer.Serialize(entry),
                cancellationToken);
            File.Move(temporaryPath, cachePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private string ComputeCacheKey(
        SignerRuleGenerationRequest request,
        string fileHash)
    {
        string material = string.Join(
            '\n',
            fileHash,
            Path.GetFullPath(request.FilePath).ToUpperInvariant(),
            request.Level,
            request.Action,
            request.SpecificFileNameLevel?.ToString() ?? string.Empty,
            Environment.OSVersion.VersionString,
            _versionToken);
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    private string GetCachePath(string key)
    {
        return Path.Combine(_cacheDirectory, $"{key}.json");
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

    private static async Task<string> ComputeFileHashAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using FileStream stream = File.OpenRead(path);
        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    private sealed class CacheMiss
    {
        public CacheMiss(SignerRuleGenerationRequest request)
        {
            Request = request;
        }

        public SignerRuleGenerationRequest Request { get; }

        public List<int> Indices { get; } = [];
    }

    private sealed class CacheEntry
    {
        public required string VersionToken { get; init; }

        public int SignerCount { get; init; }

        public int HashRuleCount { get; init; }

        public int FileAttributeCount { get; init; }

        public string? Diagnostic { get; init; }

        public required string PolicyXml { get; init; }
    }
}
