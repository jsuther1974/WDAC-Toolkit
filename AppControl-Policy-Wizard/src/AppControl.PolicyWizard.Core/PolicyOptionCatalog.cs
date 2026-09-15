namespace AppControl.PolicyWizard.Core;

public static class PolicyOptionCatalog
{
    private static readonly IReadOnlyList<PolicyOptionDefinition> DefinitionsValue =
    [
        Enabled(PolicyOptionId.UserModeCodeIntegrity, "Applications and drivers", "Enabled:UMCI", PolicyOptionScope.PolicyScoped),
        Enabled(PolicyOptionId.BootMenuProtection, "Boot menu protection", "Enabled:Boot Menu Protection", PolicyOptionScope.Unsupported, PolicyOptionSupport.Unsupported),
        Enabled(PolicyOptionId.WhqlOnlyDrivers, "Require WHQL drivers", "Required:WHQL", PolicyOptionScope.DeviceWide),
        Enabled(PolicyOptionId.AuditMode, "Audit mode", "Enabled:Audit Mode", PolicyOptionScope.PolicyScoped),
        Disabled(PolicyOptionId.FlightSigning, "Allow flight-signed code", "Disabled:Flight Signing", PolicyOptionScope.DeviceWide),
        Enabled(PolicyOptionId.InheritDefaultPolicy, "Inherit default policy", "Enabled:Inherit Default Policy", PolicyOptionScope.Unsupported, PolicyOptionSupport.Reserved),
        Enabled(PolicyOptionId.UnsignedPolicyAllowed, "Allow unsigned policy", "Enabled:Unsigned System Integrity Policy", PolicyOptionScope.DeploymentProtection, validInSupplemental: true),
        Enabled(PolicyOptionId.DebugPolicyAugmented, "Debug policy augmented", "Enabled:Debug Policy Augmented", PolicyOptionScope.Unsupported, PolicyOptionSupport.Unsupported),
        Enabled(PolicyOptionId.EvSigners, "Require EV signers", "Required:EV Signers", PolicyOptionScope.Unsupported, PolicyOptionSupport.Unsupported),
        Enabled(PolicyOptionId.AdvancedBootOptionsMenu, "Advanced boot options menu", "Enabled:Advanced Boot Options Menu", PolicyOptionScope.DeviceWide),
        Enabled(PolicyOptionId.BootAuditOnFailure, "Boot audit on failure", "Enabled:Boot Audit On Failure", PolicyOptionScope.DeviceWide),
        Disabled(PolicyOptionId.ScriptEnforcement, "Script enforcement", "Disabled:Script Enforcement", PolicyOptionScope.SpecialEnforcement),
        Enabled(PolicyOptionId.EnforceStoreApplications, "Enforce Store applications", "Required:Enforce Store Applications", PolicyOptionScope.PolicyScoped),
        Enabled(PolicyOptionId.ManagedInstaller, "Managed Installer", "Enabled:Managed Installer", PolicyOptionScope.PolicyScoped, validInSupplemental: true),
        Enabled(PolicyOptionId.MicrosoftCloudReputation, "Microsoft cloud reputation", "Enabled:Intelligent Security Graph Authorization", PolicyOptionScope.PolicyScoped, validInSupplemental: true),
        Enabled(PolicyOptionId.InvalidateEAsOnReboot, "Revalidate reputation after restart", "Enabled:Invalidate EAs on Reboot", PolicyOptionScope.DeviceWide),
        Enabled(PolicyOptionId.UpdatePolicyWithoutReboot, "Update policy without reboot", "Enabled:Update Policy No Reboot", PolicyOptionScope.PolicyScoped),
        Enabled(PolicyOptionId.AllowSupplementalPolicies, "Allow supplemental policies", "Enabled:Allow Supplemental Policies", PolicyOptionScope.PolicyScoped),
        Disabled(PolicyOptionId.RuntimeFilePathRuleProtection, "Runtime FilePath rule protection", "Disabled:Runtime FilePath Rule Protection", PolicyOptionScope.PolicyScoped, validInSupplemental: true),
        Enabled(PolicyOptionId.DynamicCodeSecurity, "Dynamic Code Security", "Enabled:Dynamic Code Security", PolicyOptionScope.SpecialEnforcement),
        Enabled(PolicyOptionId.RevokedExpiredAsUnsigned, "Treat revoked or expired signatures as unsigned", "Enabled:Revoked Expired As Unsigned", PolicyOptionScope.PolicyScoped),
        Enabled(PolicyOptionId.DeveloperModeDynamicCodeTrust, "Developer Mode dynamic code trust", "Enabled:Developer Mode Dynamic Code Trust", PolicyOptionScope.PolicyScoped),
        Enabled(PolicyOptionId.SecureSettingPolicy, "Secure setting policy", "Enabled:Secure Setting Policy", PolicyOptionScope.PlatformBehavior),
        Enabled(PolicyOptionId.ConditionalWindowsLockdownPolicy, "Conditional Windows lockdown policy", "Enabled:Conditional Windows Lockdown Policy", PolicyOptionScope.PlatformBehavior)
    ];

    private static readonly IReadOnlyDictionary<PolicyOptionId, PolicyOptionDefinition> ById =
        DefinitionsValue.ToDictionary(definition => definition.Id);

    private static readonly IReadOnlyDictionary<string, PolicyOptionDefinition> ByXmlValue =
        DefinitionsValue
            .SelectMany(definition => new[]
            {
                definition.XmlValueWhenEnabled,
                definition.XmlValueWhenDisabled
            }
            .Where(value => value is not null)
            .Select(value => new KeyValuePair<string, PolicyOptionDefinition>(value!, definition)))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);

    public static IReadOnlyList<PolicyOptionDefinition> Definitions => DefinitionsValue;

    public static PolicyOptionDefinition Get(PolicyOptionId optionId)
    {
        return ById[optionId];
    }

    public static bool TryGetByXmlValue(
        string xmlValue,
        out PolicyOptionDefinition? definition)
    {
        return ByXmlValue.TryGetValue(xmlValue, out definition);
    }

    private static PolicyOptionDefinition Enabled(
        PolicyOptionId id,
        string displayName,
        string xmlValue,
        PolicyOptionScope scope,
        PolicyOptionSupport support = PolicyOptionSupport.Supported,
        bool validInSupplemental = false)
    {
        return new PolicyOptionDefinition(
            id,
            displayName,
            xmlValue,
            XmlValueWhenDisabled: null,
            ValueWhenAbsent: false,
            scope,
            support,
            validInSupplemental);
    }

    private static PolicyOptionDefinition Disabled(
        PolicyOptionId id,
        string displayName,
        string xmlValue,
        PolicyOptionScope scope,
        bool validInSupplemental = false)
    {
        return new PolicyOptionDefinition(
            id,
            displayName,
            XmlValueWhenEnabled: null,
            xmlValue,
            ValueWhenAbsent: true,
            scope,
            PolicyOptionSupport.Supported,
            validInSupplemental);
    }
}
