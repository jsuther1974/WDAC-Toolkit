namespace AppControl.PolicyWizard.Core;

public static class FolderRuleCandidateClusterer
{
    public static void AddOrMerge(
        IList<PolicyRuleCandidate> candidates,
        PolicyRuleCandidate candidate)
    {
        int existingIndex = FindEquivalentIndex(candidates, candidate);
        if (existingIndex < 0)
        {
            candidates.Add(
                candidate with
                {
                    SupportingEvidencePaths = candidate.EvidencePaths.ToArray()
                });
            return;
        }

        PolicyRuleCandidate existing = candidates[existingIndex];
        PolicyRuleCandidate preferred = SelectBroaderObservedVersion(
            existing,
            candidate);
        string[] evidencePaths = existing.EvidencePaths
            .Concat(candidate.EvidencePaths)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        candidates[existingIndex] = preferred with
        {
            SupportingEvidencePaths = evidencePaths,
            IsRecommended = existing.IsRecommended || candidate.IsRecommended,
            IsAlreadyCovered =
                existing.IsAlreadyCovered || candidate.IsAlreadyCovered
        };
    }

    private static int FindEquivalentIndex(
        IEnumerable<PolicyRuleCandidate> candidates,
        PolicyRuleCandidate candidate)
    {
        int index = 0;
        foreach (PolicyRuleCandidate existing in candidates)
        {
            if (AreEquivalent(existing, candidate))
            {
                return index;
            }

            index++;
        }

        return -1;
    }

    private static bool AreEquivalent(
        PolicyRuleCandidate left,
        PolicyRuleCandidate right)
    {
        if (left.Action != right.Action
            || left.Identity != right.Identity
            || left.Scenario != right.Scenario
            || left.CanApply != right.CanApply)
        {
            return false;
        }

        if (left.Conditions.Count == 0 || right.Conditions.Count == 0)
        {
            return string.Equals(
                left.Title,
                right.Title,
                StringComparison.OrdinalIgnoreCase);
        }

        KeyValuePair<string, string>[] leftIdentity = left.Conditions
            .Where(condition => !IsVersionCondition(condition.Key))
            .ToArray();
        KeyValuePair<string, string>[] rightIdentity = right.Conditions
            .Where(condition => !IsVersionCondition(condition.Key))
            .ToArray();
        return leftIdentity.Length == rightIdentity.Length
            && leftIdentity.All(condition =>
                rightIdentity.Any(other =>
                    string.Equals(
                        other.Key,
                        condition.Key,
                        StringComparison.Ordinal)
                    && string.Equals(
                        other.Value,
                        condition.Value,
                        StringComparison.OrdinalIgnoreCase)));
    }

    private static bool IsVersionCondition(string key)
    {
        return key == "MinimumFileVersion"
            || key == "MaximumFileVersion"
            || key == "PackageVersion"
            || key.EndsWith(
                ".MinimumFileVersion",
                StringComparison.Ordinal)
            || key.EndsWith(
                ".MaximumFileVersion",
                StringComparison.Ordinal)
            || key.EndsWith(
                ".PackageVersion",
                StringComparison.Ordinal);
    }

    private static PolicyRuleCandidate SelectBroaderObservedVersion(
        PolicyRuleCandidate left,
        PolicyRuleCandidate right)
    {
        string? leftVersion = GetMinimumVersion(left);
        string? rightVersion = GetMinimumVersion(right);
        if (Version.TryParse(leftVersion, out Version? parsedLeft)
            && Version.TryParse(rightVersion, out Version? parsedRight)
            && parsedRight < parsedLeft)
        {
            return right;
        }

        return left;
    }

    private static string? GetMinimumVersion(PolicyRuleCandidate candidate)
    {
        return candidate.Conditions
            .FirstOrDefault(condition =>
                condition.Key == "MinimumFileVersion"
                || condition.Key.EndsWith(
                    ".MinimumFileVersion",
                    StringComparison.Ordinal))
            .Value;
    }
}
