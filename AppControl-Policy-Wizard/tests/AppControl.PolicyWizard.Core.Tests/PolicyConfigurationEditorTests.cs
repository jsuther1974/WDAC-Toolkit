using System.Xml.Linq;
using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Core.Tests;

public sealed class PolicyConfigurationEditorTests
{
    [Fact]
    public void SnapshotClassifiesKnownUnknownUnsupportedHvciAndSettings()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WriteText(
            "Policy.xml",
            """
            <?xml version="1.0" encoding="utf-8"?>
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules>
                <Rule><Option>Enabled:Audit Mode</Option></Rule>
                <Rule><Option>Disabled:Script Enforcement</Option></Rule>
                <Rule><Option>Enabled:Inherit Default Policy</Option></Rule>
                <Rule><Option>Enabled:Future Option</Option></Rule>
              </Rules>
              <HvciOptions>2</HvciOptions>
              <Settings>
                <Setting Provider="Contoso" Key="Platform" ValueName="Feature">
                  <Value><Boolean>true</Boolean></Value>
                </Setting>
              </Settings>
            </SiPolicy>
            """);

        PolicyConfigurationSnapshot snapshot = PolicyConfigurationEditor.Open(policyPath).Snapshot;

        Assert.True(snapshot.GetOption(PolicyOptionId.AuditMode).IsEnabled);
        Assert.False(snapshot.GetOption(PolicyOptionId.ScriptEnforcement).IsEnabled);
        Assert.Equal(
            PolicyOptionScope.SpecialEnforcement,
            snapshot.GetOption(PolicyOptionId.ScriptEnforcement).Definition.Scope);
        Assert.Single(snapshot.UnknownOptions);
        Assert.Equal("Enabled:Future Option", snapshot.UnknownOptions[0].XmlValue);
        Assert.Equal((uint)2, snapshot.HvciOptions);
        Assert.Contains(
            snapshot.CompatibilityFindings,
            finding => finding.Code == "reserved-option"
                && finding.XmlValue == "Enabled:Inherit Default Policy");
        PolicySettingState setting = Assert.Single(snapshot.Settings);
        Assert.Equal(new PolicySettingKey("Contoso", "Platform", "Feature"), setting.Key);
        Assert.Equal(PolicySettingValueKind.Boolean, Assert.Single(setting.Values).Kind);
    }

    [Fact]
    public void DeltaChangesOnlyRequestedOptionsAndPreservesUnknownContent()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WriteText(
            "Policy.xml",
            """
            <?xml version="1.0" encoding="utf-8"?>
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules>
                <Rule><Option>Enabled:Audit Mode</Option></Rule>
                <Rule><Option>Disabled:Script Enforcement</Option></Rule>
                <Rule><Option>Enabled:Developer Mode Dynamic Code Trust</Option></Rule>
                <Rule CustomAttribute="preserve-me"><Option>Enabled:Future Option</Option></Rule>
              </Rules>
              <Settings>
                <Setting Provider="Contoso" Key="Platform" ValueName="Feature">
                  <Value><String>preserve-me</String></Value>
                </Setting>
              </Settings>
            </SiPolicy>
            """);
        var editor = PolicyConfigurationEditor.Open(policyPath);

        PolicyConfigurationChangeResult result = editor.Apply(
            new PolicyConfigurationDelta
            {
                OptionChanges =
                [
                    new PolicyOptionChange(PolicyOptionId.AuditMode, false),
                    new PolicyOptionChange(PolicyOptionId.ScriptEnforcement, true),
                    new PolicyOptionChange(PolicyOptionId.ManagedInstaller, true)
                ]
            });

        XDocument output = editor.ToDocument();
        XNamespace ns = PolicyDocumentService.PolicyNamespace;
        string[] optionValues = output.Root!
            .Element(ns + "Rules")!
            .Elements(ns + "Rule")
            .Select(rule => rule.Element(ns + "Option")!.Value)
            .ToArray();
        Assert.DoesNotContain("Enabled:Audit Mode", optionValues);
        Assert.DoesNotContain("Disabled:Script Enforcement", optionValues);
        Assert.Contains("Enabled:Managed Installer", optionValues);
        Assert.Contains("Enabled:Developer Mode Dynamic Code Trust", optionValues);
        Assert.Contains("Enabled:Future Option", optionValues);
        Assert.Equal(
            "preserve-me",
            output.Root
                .Element(ns + "Rules")!
                .Elements(ns + "Rule")
                .Single(rule => rule.Element(ns + "Option")?.Value == "Enabled:Future Option")
                .Attribute("CustomAttribute")?
                .Value);
        Assert.Contains(
            "preserve-me",
            output.Root.Element(ns + "Settings")!.ToString());
        Assert.Equal(3, result.Changes.Count);
    }

    [Fact]
    public void DeltaUpdatesHvciAndOneSettingWithoutChangingOtherSettings()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WriteText(
            "Policy.xml",
            """
            <?xml version="1.0" encoding="utf-8"?>
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules />
              <HvciOptions>0</HvciOptions>
              <Settings>
                <Setting Provider="Contoso" Key="Keep" ValueName="Value">
                  <Value><String>unchanged</String></Value>
                </Setting>
              </Settings>
            </SiPolicy>
            """);
        var editor = PolicyConfigurationEditor.Open(policyPath);
        var settingKey = new PolicySettingKey(
            "Microsoft.Windows",
            "ApplicationControl",
            "DisableMshtmlUmci");

        editor.Apply(
            new PolicyConfigurationDelta
            {
                HvciChange = new PolicyHvciChange(2),
                SettingChanges =
                [
                    new PolicySettingChange(
                        settingKey,
                        [new PolicySettingValue(PolicySettingValueKind.Boolean, "true", "Boolean")])
                ]
            });

        PolicyConfigurationSnapshot snapshot = editor.Snapshot;
        Assert.Equal((uint)2, snapshot.HvciOptions);
        Assert.Contains(
            snapshot.Settings,
            setting => setting.Key == new PolicySettingKey("Contoso", "Keep", "Value")
                && setting.Values.Single().Value == "unchanged");
        Assert.Contains(
            snapshot.Settings,
            setting => setting.Key == settingKey
                && setting.Values.Single().Value == "true");
    }

    [Fact]
    public void UnsupportedOptionsCannotBeEnabledButCanBeRemoved()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WriteText(
            "Policy.xml",
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules><Rule><Option>Enabled:Inherit Default Policy</Option></Rule></Rules>
            </SiPolicy>
            """);
        var editor = PolicyConfigurationEditor.Open(policyPath);

        editor.Apply(
            new PolicyConfigurationDelta
            {
                OptionChanges =
                [
                    new PolicyOptionChange(PolicyOptionId.InheritDefaultPolicy, false)
                ]
            });
        Assert.False(editor.Snapshot.GetOption(PolicyOptionId.InheritDefaultPolicy).IsExplicit);

        Assert.Throws<InvalidOperationException>(
            () => editor.Apply(
                new PolicyConfigurationDelta
                {
                    OptionChanges =
                    [
                        new PolicyOptionChange(PolicyOptionId.EvSigners, true)
                    ]
                }));
    }

    [Fact]
    public void NoOpOptionDeltaDoesNotRewriteOrReorderRules()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WriteText(
            "Policy.xml",
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules>
                <Rule><Option>Enabled:Audit Mode</Option></Rule>
                <Rule><Option>Enabled:Future Option</Option></Rule>
              </Rules>
            </SiPolicy>
            """);
        var editor = PolicyConfigurationEditor.Open(policyPath);
        string before = editor.ToDocument().ToString(SaveOptions.DisableFormatting);

        PolicyConfigurationChangeResult result = editor.Apply(
            new PolicyConfigurationDelta
            {
                OptionChanges =
                [
                    new PolicyOptionChange(PolicyOptionId.AuditMode, true)
                ]
            });

        Assert.Empty(result.Changes);
        Assert.Equal(before, editor.ToDocument().ToString(SaveOptions.DisableFormatting));
    }

    [Fact]
    public void BehaviorSelectionRoundTripsWithoutCreatingChanges()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WriteText(
            "Policy.xml",
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules>
                <Rule><Option>Enabled:Audit Mode</Option></Rule>
                <Rule><Option>Enabled:UMCI</Option></Rule>
                <Rule><Option>Disabled:Script Enforcement</Option></Rule>
              </Rules>
            </SiPolicy>
            """);
        var editor = PolicyConfigurationEditor.Open(policyPath);
        PolicyBehaviorSelection selection =
            PolicyBehaviorSelection.FromSnapshot(editor.Snapshot);

        PolicyConfigurationChangeResult result = editor.Apply(selection.ToDelta());

        Assert.Equal(AppControlPolicyType.Base, editor.Snapshot.PolicyType);
        Assert.Empty(result.Changes);
    }

    [Fact]
    public void ComparerReportsNetChangesFromOriginalSnapshot()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WriteText(
            "Policy.xml",
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules>
                <Rule><Option>Enabled:Audit Mode</Option></Rule>
              </Rules>
            </SiPolicy>
            """);
        var editor = PolicyConfigurationEditor.Open(policyPath);
        PolicyConfigurationSnapshot original = editor.Snapshot;
        editor.Apply(
            new PolicyConfigurationDelta
            {
                OptionChanges =
                [
                    new PolicyOptionChange(PolicyOptionId.AuditMode, false),
                    new PolicyOptionChange(PolicyOptionId.ManagedInstaller, true)
                ]
            });

        IReadOnlyList<PolicySemanticChange> changes =
            PolicyConfigurationComparer.Compare(original, editor.Snapshot);

        Assert.Collection(
            changes,
            change => Assert.Equal("Audit mode", change.Name),
            change => Assert.Equal("Managed Installer", change.Name));
    }

    [Fact]
    public void DriversOnlySelectionRemovesDeveloperModeTrust()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WriteText(
            "Policy.xml",
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules>
                <Rule><Option>Enabled:UMCI</Option></Rule>
                <Rule><Option>Enabled:Developer Mode Dynamic Code Trust</Option></Rule>
              </Rules>
            </SiPolicy>
            """);
        var editor = PolicyConfigurationEditor.Open(policyPath);
        PolicyBehaviorSelection source =
            PolicyBehaviorSelection.FromSnapshot(editor.Snapshot);
        PolicyBehaviorSelection driversOnly = source with
        {
            UserModeCodeIntegrity = false
        };

        editor.Apply(driversOnly.ToDelta());

        Assert.False(
            editor.Snapshot
                .GetOption(PolicyOptionId.DeveloperModeDynamicCodeTrust)
                .IsEnabled);
    }
}
