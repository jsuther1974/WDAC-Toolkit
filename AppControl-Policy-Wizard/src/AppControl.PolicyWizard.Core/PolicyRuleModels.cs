namespace AppControl.PolicyWizard.Core;

using System.Xml.Linq;

public enum PolicyRuleAction
{
    Allow,
    Deny
}

public enum PolicyRuleScenario
{
    Unassigned,
    Applications,
    Drivers,
    ApplicationsAndDrivers
}

public enum PolicyRuleIdentity
{
    PcaCertificate,
    Publisher,
    FilePublisher,
    FileName,
    FilePath,
    Hash,
    Unknown
}

public enum RuleTrustBreadth
{
    ExactArtifact,
    Narrow,
    Moderate,
    Broad
}

public enum RuleUpdateResilience
{
    Low,
    Medium,
    High
}

public enum RuleEvidenceQuality
{
    Limited,
    Complete,
    Verified
}

public sealed record PolicyLogicalRule(
    string Id,
    PolicyRuleAction Action,
    PolicyRuleIdentity Identity,
    string DisplayName,
    PolicyRuleScenario Scenario,
    IReadOnlyDictionary<string, string> Conditions,
    IReadOnlyList<string> ReferencedObjectIds,
    IReadOnlyList<string> ExceptionRuleIds,
    bool IsSupported);

public sealed record PolicyRuleGraphSnapshot(
    IReadOnlyList<PolicyLogicalRule> Rules,
    IReadOnlyList<string> UnknownObjectIds)
{
    public PolicyLogicalRule? FindEquivalent(PolicyRuleCandidate candidate)
    {
        return Rules.FirstOrDefault(rule =>
            rule.Action == candidate.Action
            && rule.Identity == candidate.Identity
            && rule.Scenario == candidate.Scenario
            && candidate.Conditions.All(condition =>
                rule.Conditions.TryGetValue(condition.Key, out string? existing)
                && string.Equals(existing, condition.Value, StringComparison.OrdinalIgnoreCase)));
    }
}

public sealed record PolicyRuleCandidate(
    string Id,
    PolicyRuleAction Action,
    PolicyRuleIdentity Identity,
    PolicyRuleScenario Scenario,
    string Title,
    string Effect,
    string EvidencePath,
    IReadOnlyDictionary<string, string> Conditions,
    RuleTrustBreadth TrustBreadth,
    RuleUpdateResilience UpdateResilience,
    RuleEvidenceQuality EvidenceQuality,
    IReadOnlyList<string> Concerns,
    bool CanApply,
    string? UnavailableReason = null,
    bool IsRecommended = false,
    bool IsAlreadyCovered = false,
    PolicyRuleFragment? Fragment = null);

public sealed record PolicyRuleAddition(PolicyRuleCandidate Candidate);

public sealed record PolicyRuleChangeResult(
    PolicyRuleGraphSnapshot Snapshot,
    IReadOnlyList<PolicySemanticChange> Changes);

public sealed record PolicyRuleFragment(XDocument Document)
{
    public XDocument CloneDocument()
    {
        return new XDocument(Document);
    }
}

public enum SignerRuleLevel
{
    PcaCertificate,
    Publisher,
    FilePublisher
}

public sealed record SignerRuleGenerationRequest(
    string FilePath,
    SignerRuleLevel Level,
    PolicyRuleAction Action);

public sealed record SignerRuleGenerationResult(
    SignerRuleLevel RequestedLevel,
    PolicyRuleFragment Fragment,
    int SignerCount,
    int HashRuleCount,
    string? Diagnostic)
{
    public bool IsSignerRule => SignerCount > 0;

    public bool UsedHashFallback => HashRuleCount > 0;
}

public interface ISignerRuleGenerator
{
    Task<SignerRuleGenerationResult> GenerateAsync(
        SignerRuleGenerationRequest request,
        CancellationToken cancellationToken = default);
}
