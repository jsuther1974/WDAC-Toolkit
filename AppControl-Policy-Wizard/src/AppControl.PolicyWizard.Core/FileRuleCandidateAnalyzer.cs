using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AppControl.PolicyWizard.Core;

public sealed class FileRuleCandidateAnalyzer
{
    public IReadOnlyList<PolicyRuleCandidate> Analyze(
        string filePath,
        PolicyRuleAction action,
        PolicyRuleGraphSnapshot existingRules)
    {
        string fullPath = Path.GetFullPath(filePath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("The selected evidence file was not found.", fullPath);
        }

        FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(fullPath);
        string displayName = Path.GetFileName(fullPath);
        string? version = NormalizeVersion(versionInfo.FileVersion);
        string? originalName = NormalizeText(versionInfo.OriginalFilename)
            ?? displayName;
        string? productName = NormalizeText(versionInfo.ProductName);
        string? internalName = NormalizeText(versionInfo.InternalName);
        string? description = NormalizeText(versionInfo.FileDescription);
        X509Certificate2? certificate = TryReadCertificate(fullPath);
        PolicyRuleScenario scenario = string.Equals(
                Path.GetExtension(fullPath),
                ".sys",
                StringComparison.OrdinalIgnoreCase)
            ? PolicyRuleScenario.Drivers
            : PolicyRuleScenario.Applications;
        var candidates = new List<PolicyRuleCandidate>();

        if (certificate is not null)
        {
            var publisherConditions = new Dictionary<string, string>(
                StringComparer.Ordinal)
            {
                ["Publisher"] = certificate.GetNameInfo(
                    X509NameType.SimpleName,
                    forIssuer: false),
                ["FileName"] = originalName
            };
            if (version is not null)
            {
                publisherConditions["MinimumFileVersion"] = version;
            }

            candidates.Add(CreateCandidate(
                action,
                PolicyRuleIdentity.FilePublisher,
                scenario,
                $"Trust {displayName} by publisher and file identity",
                $"Match {publisherConditions["Publisher"]}-signed {originalName}"
                    + (version is null ? string.Empty : $" from version {version} onward"),
                fullPath,
                publisherConditions,
                RuleTrustBreadth.Narrow,
                RuleUpdateResilience.High,
                RuleEvidenceQuality.Verified,
                [],
                canApply: false,
                unavailableReason:
                    "Publisher materialization requires the ConfigCI signer-generation stage. Choose a supported alternative for this vertical slice.",
                isRecommended: true,
                existingRules));
        }

        var fileNameConditions = new Dictionary<string, string>(
            StringComparer.Ordinal)
        {
            ["FileName"] = originalName
        };
        if (version is not null)
        {
            fileNameConditions["MinimumFileVersion"] = version;
        }
        if (productName is not null)
        {
            fileNameConditions["ProductName"] = productName;
        }
        if (internalName is not null)
        {
            fileNameConditions["InternalName"] = internalName;
        }
        if (description is not null)
        {
            fileNameConditions["FileDescription"] = description;
        }

        candidates.Add(CreateCandidate(
            action,
            PolicyRuleIdentity.FileName,
            scenario,
            $"Match {displayName} by file attributes",
            $"Match file identity {originalName}"
                + (version is null ? string.Empty : $" from version {version} onward"),
            fullPath,
            fileNameConditions,
            RuleTrustBreadth.Moderate,
            RuleUpdateResilience.High,
            versionInfo.FileVersion is null
                ? RuleEvidenceQuality.Limited
                : RuleEvidenceQuality.Complete,
            certificate is null
                ? ["File attributes are not bound to a verified publisher."]
                : ["This identity is broader than the publisher-bound recommendation."],
            canApply: true,
            unavailableReason: null,
            isRecommended: certificate is null && HasUsefulFileMetadata(versionInfo),
            existingRules));

        var pathConditions = new Dictionary<string, string>(
            StringComparer.Ordinal)
        {
            ["FilePath"] = fullPath
        };
        candidates.Add(CreateCandidate(
            action,
            PolicyRuleIdentity.FilePath,
            PolicyRuleScenario.Applications,
            $"Match {displayName} by path",
            $"Match code at {fullPath}",
            fullPath,
            pathConditions,
            RuleTrustBreadth.Moderate,
            RuleUpdateResilience.Medium,
            RuleEvidenceQuality.Complete,
            ["Path trust can be unsafe if non-administrators can replace the file."],
            canApply: scenario != PolicyRuleScenario.Drivers,
            unavailableReason: scenario == PolicyRuleScenario.Drivers
                ? "FilePath rules are not valid for kernel-mode driver targeting."
                : null,
            isRecommended: false,
            existingRules));

        using FileStream stream = File.OpenRead(fullPath);
        string hash = Convert.ToHexString(SHA256.HashData(stream));
        var hashConditions = new Dictionary<string, string>(
            StringComparer.Ordinal)
        {
            ["Hash"] = hash
        };
        candidates.Add(CreateCandidate(
            action,
            PolicyRuleIdentity.Hash,
            scenario,
            $"Match this exact {displayName} binary",
            $"Match SHA-256 {hash}",
            fullPath,
            hashConditions,
            RuleTrustBreadth.ExactArtifact,
            RuleUpdateResilience.Low,
            RuleEvidenceQuality.Verified,
            ["The rule must be replaced whenever the file content changes."],
            canApply: true,
            unavailableReason: null,
            isRecommended: certificate is null && !HasUsefulFileMetadata(versionInfo),
            existingRules));

        return candidates;
    }

    public PolicyRuleCandidate CreateManual(
        PolicyRuleAction action,
        PolicyRuleIdentity identity,
        PolicyRuleScenario scenario,
        string value,
        string? minimumVersion,
        PolicyRuleGraphSnapshot existingRules)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException("Enter a value for the manual rule.");
        }

        var conditions = new Dictionary<string, string>(StringComparer.Ordinal);
        RuleTrustBreadth breadth;
        RuleUpdateResilience resilience;
        string effect;
        IReadOnlyList<string> concerns;
        switch (identity)
        {
            case PolicyRuleIdentity.FilePath:
                if (scenario != PolicyRuleScenario.Applications)
                {
                    throw new InvalidOperationException(
                        "FilePath rules can target applications only.");
                }

                conditions["FilePath"] = value.Trim();
                breadth = RuleTrustBreadth.Moderate;
                resilience = RuleUpdateResilience.Medium;
                effect = $"Match code at {value.Trim()}";
                concerns = ["Verify that non-administrators cannot write to the selected path."];
                break;
            case PolicyRuleIdentity.Hash:
                string hash = value.Replace(" ", string.Empty, StringComparison.Ordinal);
                if (hash.Length is not 40 and not 64
                    || hash.Any(character => !Uri.IsHexDigit(character)))
                {
                    throw new InvalidDataException(
                        "Enter a SHA-1 or SHA-256 hexadecimal hash.");
                }

                conditions["Hash"] = hash.ToUpperInvariant();
                breadth = RuleTrustBreadth.ExactArtifact;
                resilience = RuleUpdateResilience.Low;
                effect = $"Match hash {conditions["Hash"]}";
                concerns = ["The rule must be replaced whenever the file content changes."];
                break;
            case PolicyRuleIdentity.FileName:
                string? normalizedMinimumVersion = NormalizeVersion(minimumVersion);
                if (!string.IsNullOrWhiteSpace(minimumVersion)
                    && normalizedMinimumVersion is null)
                {
                    throw new InvalidDataException(
                        "Enter a valid dotted minimum version, such as 1.0.0.0.");
                }

                conditions["FileName"] = value.Trim();
                if (normalizedMinimumVersion is not null)
                {
                    conditions["MinimumFileVersion"] = normalizedMinimumVersion;
                }

                breadth = RuleTrustBreadth.Broad;
                resilience = RuleUpdateResilience.High;
                effect = $"Match file identity {value.Trim()}"
                    + (normalizedMinimumVersion is null
                        ? string.Empty
                        : $" from version {normalizedMinimumVersion} onward");
                concerns = ["Manual file attributes are not bound to a verified publisher."];
                break;
            default:
                throw new InvalidOperationException(
                    $"Manual {identity} rules are not supported by this release.");
        }

        return CreateCandidate(
            action,
            identity,
            scenario,
            $"Manual {identity} rule",
            effect,
            "Manual entry",
            conditions,
            breadth,
            resilience,
            RuleEvidenceQuality.Limited,
            concerns,
            canApply: true,
            unavailableReason: null,
            isRecommended: true,
            existingRules);
    }

    private static PolicyRuleCandidate CreateCandidate(
        PolicyRuleAction action,
        PolicyRuleIdentity identity,
        PolicyRuleScenario scenario,
        string title,
        string effect,
        string evidencePath,
        IReadOnlyDictionary<string, string> conditions,
        RuleTrustBreadth trustBreadth,
        RuleUpdateResilience updateResilience,
        RuleEvidenceQuality evidenceQuality,
        IReadOnlyList<string> concerns,
        bool canApply,
        string? unavailableReason,
        bool isRecommended,
        PolicyRuleGraphSnapshot existingRules)
    {
        var candidate = new PolicyRuleCandidate(
            Guid.NewGuid().ToString("N"),
            action,
            identity,
            scenario,
            title,
            effect,
            evidencePath,
            conditions,
            trustBreadth,
            updateResilience,
            evidenceQuality,
            concerns,
            canApply,
            unavailableReason,
            isRecommended);
        return candidate with
        {
            IsAlreadyCovered = existingRules.FindEquivalent(candidate) is not null
        };
    }

    private static X509Certificate2? TryReadCertificate(string path)
    {
        try
        {
            using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
            return new X509Certificate2(certificate);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static bool HasUsefulFileMetadata(FileVersionInfo versionInfo)
    {
        return NormalizeText(versionInfo.OriginalFilename) is not null
            && NormalizeVersion(versionInfo.FileVersion) is not null;
    }

    private static string? NormalizeText(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static string? NormalizeVersion(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string normalized = value.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
        if (!Version.TryParse(normalized, out Version? version))
        {
            return null;
        }

        return string.Join(
            ".",
            version.Major,
            version.Minor,
            Math.Max(0, version.Build),
            Math.Max(0, version.Revision));
    }
}
