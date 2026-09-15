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
        PolicyRuleIdentity identity = result.RequestedLevel switch
        {
            SignerRuleLevel.PcaCertificate => PolicyRuleIdentity.PcaCertificate,
            SignerRuleLevel.Publisher => PolicyRuleIdentity.Publisher,
            _ => PolicyRuleIdentity.FilePublisher
        };
        string fileName = Path.GetFileName(filePath);
        string identityName = identity switch
        {
            PolicyRuleIdentity.PcaCertificate => "issuing certificate",
            PolicyRuleIdentity.Publisher => "publisher",
            _ => "publisher and file identity"
        };
        string effect = generatedSigner is null
            ? $"No {identityName} rule could be generated for {fileName}"
            : $"Match {fileName} by {identityName}";
        bool canApply = result.IsSignerRule && !result.UsedHashFallback;
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

        IReadOnlyDictionary<string, string> conditions =
            generatedSigner?.Conditions
            ?? new Dictionary<string, string>(StringComparer.Ordinal);
        var candidate = new PolicyRuleCandidate(
            Guid.NewGuid().ToString("N"),
            result.Fragment.Document.Root?
                .Descendants(
                    XNamespace.Get(PolicyDocumentService.PolicyNamespace)
                    + "DeniedSigner")
                .Any() == true
                ? PolicyRuleAction.Deny
                : PolicyRuleAction.Allow,
            identity,
            scenario,
            $"{fileName}: {GetDisplayName(identity)}",
            effect,
            Path.GetFullPath(filePath),
            conditions,
            identity switch
            {
                PolicyRuleIdentity.PcaCertificate => RuleTrustBreadth.Broad,
                PolicyRuleIdentity.Publisher => RuleTrustBreadth.Moderate,
                _ => RuleTrustBreadth.Narrow
            },
            RuleUpdateResilience.High,
            generatedSigner is null
                ? RuleEvidenceQuality.Limited
                : RuleEvidenceQuality.Verified,
            concerns,
            canApply,
            canApply
                ? null
                : result.Diagnostic
                    ?? "The requested signer rule could not be generated without fallback.",
            IsRecommended: identity == PolicyRuleIdentity.FilePublisher && canApply,
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
        bool isRecommended)
    {
        PolicyRuleIdentity identity = level switch
        {
            SignerRuleLevel.PcaCertificate => PolicyRuleIdentity.PcaCertificate,
            SignerRuleLevel.Publisher => PolicyRuleIdentity.Publisher,
            _ => PolicyRuleIdentity.FilePublisher
        };
        string fileName = Path.GetFileName(filePath);
        return new PolicyRuleCandidate(
            Guid.NewGuid().ToString("N"),
            action,
            identity,
            scenario,
            $"{fileName}: {GetDisplayName(identity)}",
            $"No {GetDisplayName(identity).ToLowerInvariant()} rule could be generated for {fileName}",
            Path.GetFullPath(filePath),
            new Dictionary<string, string>(StringComparer.Ordinal),
            identity switch
            {
                PolicyRuleIdentity.PcaCertificate => RuleTrustBreadth.Broad,
                PolicyRuleIdentity.Publisher => RuleTrustBreadth.Moderate,
                _ => RuleTrustBreadth.Narrow
            },
            RuleUpdateResilience.High,
            RuleEvidenceQuality.Limited,
            [reason],
            CanApply: false,
            UnavailableReason: reason,
            IsRecommended: isRecommended);
    }

    private static string GetDisplayName(PolicyRuleIdentity identity)
    {
        return identity switch
        {
            PolicyRuleIdentity.PcaCertificate => "Issuing certificate",
            PolicyRuleIdentity.Publisher => "Publisher",
            _ => "Publisher and file identity"
        };
    }
}
