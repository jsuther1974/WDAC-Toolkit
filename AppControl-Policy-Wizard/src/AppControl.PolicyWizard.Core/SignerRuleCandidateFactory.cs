namespace AppControl.PolicyWizard.Core;

using System.Xml.Linq;

public static class SignerRuleCandidateFactory
{
    public static PolicyRuleCandidate Create(
        string filePath,
        PolicyRuleScenario scenario,
        SignerRuleGenerationResult result,
        PolicyRuleGraphSnapshot existingRules)
    {
        ArgumentNullException.ThrowIfNull(result);
        PolicyRuleGraphSnapshot generatedGraph =
            PolicyRuleGraphEditor.FromDocument(
                result.Fragment.CloneDocument()).Snapshot;
        PolicyLogicalRule? generatedSigner = generatedGraph.Rules
            .FirstOrDefault(rule => rule.Identity is PolicyRuleIdentity.PcaCertificate
                or PolicyRuleIdentity.Publisher
                or PolicyRuleIdentity.FilePublisher);
        PolicyRuleIdentity identity = GetIdentity(result.RequestedLevel);
        SignerFileNameLevel? fileNameLevel =
            identity == PolicyRuleIdentity.FilePublisher
                ? result.SpecificFileNameLevel
                    ?? SignerFileNameLevel.OriginalFileName
                : null;
        bool identityMatches = generatedSigner?.Identity == identity;
        bool fileAttributeMatches = identity != PolicyRuleIdentity.FilePublisher
            || result.FileAttributeCount > 0;
        bool canApply = result.IsSignerRule
            && !result.UsedHashFallback
            && identityMatches
            && fileAttributeMatches;
        string fileName = Path.GetFileName(filePath);
        IReadOnlyDictionary<string, string> conditions =
            generatedSigner?.Conditions
            ?? new Dictionary<string, string>(StringComparer.Ordinal);
        string displayName = GetDisplayName(
            identity,
            fileNameLevel,
            conditions);
        string effect = canApply
            ? GetEffect(fileName, identity, fileNameLevel, conditions)
            : $"No {displayName.ToLowerInvariant()} rule could be generated for {fileName}";
        var concerns = GetConcerns(
            identity,
            fileNameLevel,
            result,
            identityMatches,
            fileAttributeMatches);
        string? unavailableReason = canApply
            ? null
            : result.Diagnostic
                ?? concerns.FirstOrDefault()
                ?? "The requested signer rule could not be generated without fallback.";
        var candidate = new PolicyRuleCandidate(
            Guid.NewGuid().ToString("N"),
            GetAction(result.Fragment.Document),
            identity,
            scenario,
            $"{fileName}: {displayName}",
            effect,
            Path.GetFullPath(filePath),
            conditions,
            GetTrustBreadth(identity, fileNameLevel),
            GetUpdateResilience(identity, fileNameLevel),
            canApply
                ? RuleEvidenceQuality.Verified
                : RuleEvidenceQuality.Limited,
            concerns,
            canApply,
            unavailableReason,
            IsRecommended:
                identity == PolicyRuleIdentity.FilePublisher
                && fileNameLevel == SignerFileNameLevel.OriginalFileName
                && canApply,
            IsAlreadyCovered: false,
            canApply ? result.Fragment : null);
        return candidate with
        {
            IsAlreadyCovered = existingRules.FindEquivalent(candidate) is not null
        };
    }

    public static PolicyRuleCandidate CreateUnavailable(
        string filePath,
        PolicyRuleScenario scenario,
        SignerRuleLevel level,
        PolicyRuleAction action,
        string reason,
        bool isRecommended,
        SignerFileNameLevel? specificFileNameLevel = null)
    {
        PolicyRuleIdentity identity = GetIdentity(level);
        SignerFileNameLevel? fileNameLevel =
            identity == PolicyRuleIdentity.FilePublisher
                ? specificFileNameLevel
                    ?? SignerFileNameLevel.OriginalFileName
                : null;
        string fileName = Path.GetFileName(filePath);
        string displayName = GetDisplayName(
            identity,
            fileNameLevel,
            new Dictionary<string, string>(StringComparer.Ordinal));
        return new PolicyRuleCandidate(
            Guid.NewGuid().ToString("N"),
            action,
            identity,
            scenario,
            $"{fileName}: {displayName}",
            $"No {displayName.ToLowerInvariant()} rule could be generated for {fileName}",
            Path.GetFullPath(filePath),
            new Dictionary<string, string>(StringComparer.Ordinal),
            GetTrustBreadth(identity, fileNameLevel),
            GetUpdateResilience(identity, fileNameLevel),
            RuleEvidenceQuality.Limited,
            [reason],
            CanApply: false,
            UnavailableReason: reason,
            IsRecommended: isRecommended);
    }

    private static PolicyRuleAction GetAction(XDocument fragment)
    {
        XNamespace policyNamespace =
            XNamespace.Get(PolicyDocumentService.PolicyNamespace);
        return fragment.Root?
            .Descendants(policyNamespace + "DeniedSigner")
            .Any() == true
            ? PolicyRuleAction.Deny
            : PolicyRuleAction.Allow;
    }

    private static PolicyRuleIdentity GetIdentity(SignerRuleLevel level)
    {
        return level switch
        {
            SignerRuleLevel.PcaCertificate => PolicyRuleIdentity.PcaCertificate,
            SignerRuleLevel.Publisher => PolicyRuleIdentity.Publisher,
            _ => PolicyRuleIdentity.FilePublisher
        };
    }

    private static string GetDisplayName(
        PolicyRuleIdentity identity,
        SignerFileNameLevel? fileNameLevel,
        IReadOnlyDictionary<string, string> conditions)
    {
        string displayName = identity switch
        {
            PolicyRuleIdentity.PcaCertificate => "Issuing certificate",
            PolicyRuleIdentity.Publisher => "Publisher",
            _ => $"Publisher + {GetFileNameLevelDisplayName(fileNameLevel!.Value)}"
        };
        return conditions.ContainsKey("CertOemID")
            ? $"{displayName} + OPUS"
            : displayName;
    }

    private static string GetFileNameLevelDisplayName(
        SignerFileNameLevel fileNameLevel)
    {
        return fileNameLevel switch
        {
            SignerFileNameLevel.OriginalFileName => "original filename",
            SignerFileNameLevel.InternalName => "internal name",
            SignerFileNameLevel.FileDescription => "file description",
            SignerFileNameLevel.ProductName => "product name",
            SignerFileNameLevel.PackageFamilyName => "package family name",
            SignerFileNameLevel.FilePath => "file path",
            _ => fileNameLevel.ToString()
        };
    }

    private static string GetEffect(
        string fileName,
        PolicyRuleIdentity identity,
        SignerFileNameLevel? fileNameLevel,
        IReadOnlyDictionary<string, string> conditions)
    {
        if (identity != PolicyRuleIdentity.FilePublisher)
        {
            string signerEffect = identity == PolicyRuleIdentity.Publisher
                ? $"Match {fileName} by publisher"
                : $"Match {fileName} by issuing certificate";
            return AppendSignerConstraints(signerEffect, conditions);
        }

        string conditionKey = fileNameLevel switch
        {
            SignerFileNameLevel.OriginalFileName => "FileAttribute[0].FileName",
            SignerFileNameLevel.InternalName => "FileAttribute[0].InternalName",
            SignerFileNameLevel.FileDescription => "FileAttribute[0].FileDescription",
            SignerFileNameLevel.ProductName => "FileAttribute[0].ProductName",
            SignerFileNameLevel.PackageFamilyName => "FileAttribute[0].PackageFamilyName",
            SignerFileNameLevel.FilePath => "FileAttribute[0].FilePath",
            _ => string.Empty
        };
        string? value = conditions.GetValueOrDefault(conditionKey);
        string selector = GetFileNameLevelDisplayName(fileNameLevel!.Value);
        string effect = string.IsNullOrWhiteSpace(value)
            ? $"Match {fileName} by publisher and {selector}"
            : $"Match publisher-signed code where {selector} is {value}";
        string? minimumVersion =
            conditions.GetValueOrDefault("FileAttribute[0].MinimumFileVersion");
        string? maximumVersion =
            conditions.GetValueOrDefault("FileAttribute[0].MaximumFileVersion");
        if (!string.IsNullOrWhiteSpace(minimumVersion)
            && !string.IsNullOrWhiteSpace(maximumVersion))
        {
            effect += $" from version {minimumVersion} through {maximumVersion}";
        }
        else if (!string.IsNullOrWhiteSpace(minimumVersion))
        {
            effect += $" from version {minimumVersion} onward";
        }
        else if (!string.IsNullOrWhiteSpace(maximumVersion))
        {
            effect += $" through version {maximumVersion}";
        }

        if (conditions.GetValueOrDefault("FileAttribute[0].PackageVersion")
            is string packageVersion
            && !string.IsNullOrWhiteSpace(packageVersion))
        {
            effect += $" for package version {packageVersion}";
        }

        return AppendSignerConstraints(effect, conditions);
    }

    private static string AppendSignerConstraints(
        string effect,
        IReadOnlyDictionary<string, string> conditions)
    {
        var constraints = new List<string>();
        if (conditions.GetValueOrDefault("CertOemID") is string opus
            && !string.IsNullOrWhiteSpace(opus))
        {
            constraints.Add($"OPUS identity {opus}");
        }

        int ekuCount = conditions.Keys.Count(key =>
            key == "CertEKU"
            || key.StartsWith("CertEKU[", StringComparison.Ordinal));
        if (ekuCount > 0)
        {
            constraints.Add(
                ekuCount == 1
                    ? "1 EKU constraint"
                    : $"{ekuCount} EKU constraints");
        }

        return constraints.Count == 0
            ? effect
            : $"{effect}; require {string.Join(" and ", constraints)}";
    }

    private static IReadOnlyList<string> GetConcerns(
        PolicyRuleIdentity identity,
        SignerFileNameLevel? fileNameLevel,
        SignerRuleGenerationResult result,
        bool identityMatches,
        bool fileAttributeMatches)
    {
        var concerns = new List<string>();
        if (result.UsedHashFallback)
        {
            concerns.Add(
                "ConfigCI returned hash fallback rules instead of the requested signer identity.");
        }
        if (!result.IsSignerRule)
        {
            concerns.Add(
                result.Diagnostic
                ?? "No signer rule was returned for this file and identity level.");
        }
        else if (!identityMatches || !fileAttributeMatches)
        {
            concerns.Add(
                result.Diagnostic
                ?? "ConfigCI returned a broader signer without the requested file attribute.");
        }

        if (identity == PolicyRuleIdentity.PcaCertificate)
        {
            concerns.Add(
                "This broad identity can trust code from multiple publishers under the same issuing certificate.");
        }
        else if (identity == PolicyRuleIdentity.Publisher)
        {
            concerns.Add(
                "This identity trusts other code signed by the same publisher.");
        }
        else
        {
            concerns.AddRange(GetFileNameLevelConcerns(fileNameLevel!.Value));
        }

        return concerns;
    }

    private static IEnumerable<string> GetFileNameLevelConcerns(
        SignerFileNameLevel fileNameLevel)
    {
        return fileNameLevel switch
        {
            SignerFileNameLevel.InternalName =>
            [
                "Internal names can be shared by multiple binaries from the publisher."
            ],
            SignerFileNameLevel.FileDescription =>
            [
                "File descriptions are descriptive metadata and may be reused across binaries."
            ],
            SignerFileNameLevel.ProductName =>
            [
                "Product names can intentionally trust multiple binaries in the same product."
            ],
            SignerFileNameLevel.PackageFamilyName =>
            [
                "Package family trust should be reviewed with the policy's packaged-app strategy."
            ],
            SignerFileNameLevel.FilePath =>
            [
                "The file must remain at this path and retain the matching publisher signature."
            ],
            _ => []
        };
    }

    private static RuleTrustBreadth GetTrustBreadth(
        PolicyRuleIdentity identity,
        SignerFileNameLevel? fileNameLevel)
    {
        if (identity == PolicyRuleIdentity.PcaCertificate)
        {
            return RuleTrustBreadth.Broad;
        }

        if (identity == PolicyRuleIdentity.Publisher)
        {
            return RuleTrustBreadth.Moderate;
        }

        return fileNameLevel switch
        {
            SignerFileNameLevel.OriginalFileName => RuleTrustBreadth.Narrow,
            SignerFileNameLevel.FilePath => RuleTrustBreadth.Narrow,
            SignerFileNameLevel.PackageFamilyName => RuleTrustBreadth.Moderate,
            SignerFileNameLevel.InternalName => RuleTrustBreadth.Moderate,
            _ => RuleTrustBreadth.Broad
        };
    }

    private static RuleUpdateResilience GetUpdateResilience(
        PolicyRuleIdentity identity,
        SignerFileNameLevel? fileNameLevel)
    {
        return identity == PolicyRuleIdentity.FilePublisher
            && fileNameLevel == SignerFileNameLevel.FilePath
                ? RuleUpdateResilience.Medium
                : RuleUpdateResilience.High;
    }
}
