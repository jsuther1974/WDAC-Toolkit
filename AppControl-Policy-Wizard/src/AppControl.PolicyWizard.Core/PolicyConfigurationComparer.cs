namespace AppControl.PolicyWizard.Core;

public static class PolicyConfigurationComparer
{
    public static IReadOnlyList<PolicySemanticChange> Compare(
        PolicyConfigurationSnapshot before,
        PolicyConfigurationSnapshot after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        var changes = new List<PolicySemanticChange>();

        foreach (PolicyOptionState beforeOption in before.Options)
        {
            PolicyOptionState afterOption = after.GetOption(beforeOption.Definition.Id);
            if (beforeOption.IsEnabled == afterOption.IsEnabled)
            {
                continue;
            }

            changes.Add(
                new PolicySemanticChange(
                    "Policy option",
                    beforeOption.Definition.DisplayName,
                    beforeOption.IsEnabled ? "Enabled" : "Disabled",
                    afterOption.IsEnabled ? "Enabled" : "Disabled"));
        }

        if (before.HvciOptions != after.HvciOptions
            || !string.Equals(
                before.RawHvciOptions,
                after.RawHvciOptions,
                StringComparison.Ordinal))
        {
            changes.Add(
                new PolicySemanticChange(
                    "Device-wide runtime",
                    "HVCI",
                    before.RawHvciOptions ?? "(not specified)",
                    after.RawHvciOptions ?? "(not specified)"));
        }

        var beforeSettings = before.Settings.ToDictionary(
            setting => setting.Key,
            setting => setting.RawXml);
        var afterSettings = after.Settings.ToDictionary(
            setting => setting.Key,
            setting => setting.RawXml);
        foreach (PolicySettingKey key in beforeSettings.Keys
            .Concat(afterSettings.Keys)
            .Distinct())
        {
            beforeSettings.TryGetValue(key, out string? beforeValue);
            afterSettings.TryGetValue(key, out string? afterValue);
            if (string.Equals(beforeValue, afterValue, StringComparison.Ordinal))
            {
                continue;
            }

            changes.Add(
                new PolicySemanticChange(
                    "Platform behavior",
                    $"{key.Provider}/{key.Key}/{key.ValueName}",
                    beforeValue is null ? "(not specified)" : "Configured",
                    afterValue is null ? "(removed)" : "Configured"));
        }

        return changes;
    }
}
