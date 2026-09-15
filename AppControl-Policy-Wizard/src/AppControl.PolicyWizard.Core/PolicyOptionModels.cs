namespace AppControl.PolicyWizard.Core;

public enum PolicyOptionId
{
    UserModeCodeIntegrity,
    BootMenuProtection,
    WhqlOnlyDrivers,
    AuditMode,
    FlightSigning,
    InheritDefaultPolicy,
    UnsignedPolicyAllowed,
    DebugPolicyAugmented,
    EvSigners,
    AdvancedBootOptionsMenu,
    BootAuditOnFailure,
    ScriptEnforcement,
    EnforceStoreApplications,
    ManagedInstaller,
    MicrosoftCloudReputation,
    InvalidateEAsOnReboot,
    UpdatePolicyWithoutReboot,
    AllowSupplementalPolicies,
    RuntimeFilePathRuleProtection,
    DynamicCodeSecurity,
    RevokedExpiredAsUnsigned,
    DeveloperModeDynamicCodeTrust,
    SecureSettingPolicy,
    ConditionalWindowsLockdownPolicy
}

public enum PolicyOptionScope
{
    PolicyScoped,
    DeviceWide,
    SpecialEnforcement,
    DeploymentProtection,
    PlatformBehavior,
    Unsupported
}

public enum PolicyOptionSupport
{
    Supported,
    Unsupported,
    Reserved
}

public enum AppControlPolicyType
{
    Base,
    Supplemental,
    AppIdTagging,
    Unknown
}

public sealed record PolicyOptionDefinition(
    PolicyOptionId Id,
    string DisplayName,
    string? XmlValueWhenEnabled,
    string? XmlValueWhenDisabled,
    bool ValueWhenAbsent,
    PolicyOptionScope Scope,
    PolicyOptionSupport Support,
    bool ValidInSupplemental);

public sealed record PolicyOptionState(
    PolicyOptionDefinition Definition,
    bool IsEnabled,
    bool IsExplicit,
    string? SourceXmlValue);

public sealed record UnknownPolicyOption(string XmlValue, string RawXml);

public sealed record PolicyCompatibilityFinding(
    string Code,
    string Message,
    string? XmlValue = null);

public readonly record struct PolicySettingKey(
    string Provider,
    string Key,
    string ValueName);

public enum PolicySettingValueKind
{
    Boolean,
    DWord,
    String,
    Binary,
    Unknown
}

public sealed record PolicySettingValue(
    PolicySettingValueKind Kind,
    string Value,
    string ElementName);

public sealed record PolicySettingState(
    PolicySettingKey Key,
    IReadOnlyList<PolicySettingValue> Values,
    string RawXml);

public sealed record PolicyConfigurationSnapshot(
    AppControlPolicyType PolicyType,
    IReadOnlyList<PolicyOptionState> Options,
    IReadOnlyList<UnknownPolicyOption> UnknownOptions,
    uint? HvciOptions,
    string? RawHvciOptions,
    IReadOnlyList<PolicySettingState> Settings,
    IReadOnlyList<PolicyCompatibilityFinding> CompatibilityFindings)
{
    public PolicyOptionState GetOption(PolicyOptionId optionId)
    {
        return Options.First(option => option.Definition.Id == optionId);
    }
}

public sealed record PolicyBehaviorSelection(
    bool AuditMode,
    bool UserModeCodeIntegrity,
    bool MicrosoftCloudReputation,
    bool ManagedInstaller,
    bool AllowSupplementalPolicies,
    bool ScriptEnforcement,
    bool DynamicCodeSecurity,
    bool WhqlOnlyDrivers,
    bool FlightSigning,
    bool AdvancedBootOptionsMenu,
    bool BootAuditOnFailure,
    bool InvalidateEAsOnReboot,
    bool UpdatePolicyWithoutReboot,
    bool EnforceStoreApplications,
    bool RuntimeFilePathRuleProtection,
    bool RevokedExpiredAsUnsigned)
{
    public static PolicyBehaviorSelection FromSnapshot(
        PolicyConfigurationSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return new PolicyBehaviorSelection(
            snapshot.GetOption(PolicyOptionId.AuditMode).IsEnabled,
            snapshot.GetOption(PolicyOptionId.UserModeCodeIntegrity).IsEnabled,
            snapshot.GetOption(PolicyOptionId.MicrosoftCloudReputation).IsEnabled,
            snapshot.GetOption(PolicyOptionId.ManagedInstaller).IsEnabled,
            snapshot.GetOption(PolicyOptionId.AllowSupplementalPolicies).IsEnabled,
            snapshot.GetOption(PolicyOptionId.ScriptEnforcement).IsEnabled,
            snapshot.GetOption(PolicyOptionId.DynamicCodeSecurity).IsEnabled,
            snapshot.GetOption(PolicyOptionId.WhqlOnlyDrivers).IsEnabled,
            snapshot.GetOption(PolicyOptionId.FlightSigning).IsEnabled,
            snapshot.GetOption(PolicyOptionId.AdvancedBootOptionsMenu).IsEnabled,
            snapshot.GetOption(PolicyOptionId.BootAuditOnFailure).IsEnabled,
            snapshot.GetOption(PolicyOptionId.InvalidateEAsOnReboot).IsEnabled,
            snapshot.GetOption(PolicyOptionId.UpdatePolicyWithoutReboot).IsEnabled,
            snapshot.GetOption(PolicyOptionId.EnforceStoreApplications).IsEnabled,
            snapshot.GetOption(PolicyOptionId.RuntimeFilePathRuleProtection).IsEnabled,
            snapshot.GetOption(PolicyOptionId.RevokedExpiredAsUnsigned).IsEnabled);
    }

    public PolicyConfigurationDelta ToDelta()
    {
        var optionChanges = new List<PolicyOptionChange>
        {
            new(PolicyOptionId.AuditMode, AuditMode),
            new(PolicyOptionId.UserModeCodeIntegrity, UserModeCodeIntegrity),
            new(PolicyOptionId.MicrosoftCloudReputation, MicrosoftCloudReputation),
            new(PolicyOptionId.ManagedInstaller, ManagedInstaller),
            new(PolicyOptionId.AllowSupplementalPolicies, AllowSupplementalPolicies),
            new(PolicyOptionId.ScriptEnforcement, ScriptEnforcement),
            new(PolicyOptionId.DynamicCodeSecurity, DynamicCodeSecurity),
            new(PolicyOptionId.WhqlOnlyDrivers, WhqlOnlyDrivers),
            new(PolicyOptionId.FlightSigning, FlightSigning),
            new(PolicyOptionId.AdvancedBootOptionsMenu, AdvancedBootOptionsMenu),
            new(PolicyOptionId.BootAuditOnFailure, BootAuditOnFailure),
            new(PolicyOptionId.InvalidateEAsOnReboot, InvalidateEAsOnReboot),
            new(PolicyOptionId.UpdatePolicyWithoutReboot, UpdatePolicyWithoutReboot),
            new(PolicyOptionId.EnforceStoreApplications, EnforceStoreApplications),
            new(PolicyOptionId.RuntimeFilePathRuleProtection, RuntimeFilePathRuleProtection),
            new(PolicyOptionId.RevokedExpiredAsUnsigned, RevokedExpiredAsUnsigned)
        };
        if (!UserModeCodeIntegrity)
        {
            optionChanges.Add(
                new PolicyOptionChange(
                    PolicyOptionId.DeveloperModeDynamicCodeTrust,
                    false));
        }

        return new PolicyConfigurationDelta
        {
            OptionChanges = optionChanges
        };
    }
}

public sealed record PolicyOptionChange(PolicyOptionId OptionId, bool IsEnabled);

public sealed record PolicyHvciChange(uint Value);

public sealed record PolicySettingChange(
    PolicySettingKey Key,
    IReadOnlyList<PolicySettingValue>? Values);

public sealed class PolicyConfigurationDelta
{
    public IReadOnlyList<PolicyOptionChange> OptionChanges { get; init; } = [];

    public PolicyHvciChange? HvciChange { get; init; }

    public IReadOnlyList<PolicySettingChange> SettingChanges { get; init; } = [];
}

public sealed record PolicySemanticChange(
    string Category,
    string Name,
    string? Before,
    string? After);

public sealed record PolicyConfigurationChangeResult(
    PolicyConfigurationSnapshot Snapshot,
    IReadOnlyList<PolicySemanticChange> Changes);
