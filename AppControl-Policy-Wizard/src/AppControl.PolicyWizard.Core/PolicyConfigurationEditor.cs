using System.Globalization;
using System.Xml.Linq;

namespace AppControl.PolicyWizard.Core;

public sealed class PolicyConfigurationEditor
{
    private readonly XDocument _document;
    private readonly XNamespace _namespace = PolicyDocumentService.PolicyNamespace;

    private PolicyConfigurationEditor(XDocument document)
    {
        _document = document;
    }

    public PolicyConfigurationSnapshot Snapshot => CreateSnapshot(_document);

    public static PolicyConfigurationEditor Open(string policyPath)
    {
        XDocument document = new PolicyDocumentService().Load(policyPath);
        return new PolicyConfigurationEditor(document);
    }

    public static PolicyConfigurationEditor FromDocument(XDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        XName expectedRoot = XName.Get("SiPolicy", PolicyDocumentService.PolicyNamespace);
        if (document.Root?.Name != expectedRoot)
        {
            throw new InvalidDataException("The document is not a valid App Control policy.");
        }

        return new PolicyConfigurationEditor(new XDocument(document));
    }

    public PolicyConfigurationChangeResult Apply(PolicyConfigurationDelta delta)
    {
        ArgumentNullException.ThrowIfNull(delta);
        var changes = new List<PolicySemanticChange>();

        foreach (PolicyOptionChange optionChange in delta.OptionChanges)
        {
            ApplyOptionChange(optionChange, changes);
        }

        if (delta.HvciChange is not null)
        {
            ApplyHvciChange(delta.HvciChange, changes);
        }

        foreach (PolicySettingChange settingChange in delta.SettingChanges)
        {
            ApplySettingChange(settingChange, changes);
        }

        return new PolicyConfigurationChangeResult(Snapshot, changes);
    }

    public XDocument ToDocument()
    {
        return new XDocument(_document);
    }

    public PolicyRuleGraphSnapshot RuleGraph =>
        PolicyRuleGraphEditor.FromDocument(_document).Snapshot;

    public PolicyRuleChangeResult ApplyRules(
        IEnumerable<PolicyRuleAddition> additions)
    {
        PolicyRuleGraphEditor editor = PolicyRuleGraphEditor.FromDocument(_document);
        PolicyRuleChangeResult result = editor.Apply(additions);
        XDocument updated = editor.ToDocument();
        _document.RemoveNodes();
        _document.Add(updated.Root!);
        return result;
    }

    public void Save(string outputPath)
    {
        string fullPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(
            Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("The output path has no parent directory."));
        _document.Save(fullPath, SaveOptions.DisableFormatting);
    }

    private void ApplyOptionChange(
        PolicyOptionChange change,
        ICollection<PolicySemanticChange> changes)
    {
        PolicyOptionDefinition definition = PolicyOptionCatalog.Get(change.OptionId);
        if (definition.Support != PolicyOptionSupport.Supported && change.IsEnabled)
        {
            throw new InvalidOperationException(
                $"The option '{definition.DisplayName}' is {definition.Support.ToString().ToLowerInvariant()} and cannot be enabled.");
        }

        PolicyOptionState before = Snapshot.GetOption(change.OptionId);
        if (before.IsEnabled == change.IsEnabled)
        {
            return;
        }

        string? desiredXmlValue = change.IsEnabled
            ? definition.XmlValueWhenEnabled
            : definition.XmlValueWhenDisabled;

        RemoveOptionRules(definition.XmlValueWhenEnabled);
        RemoveOptionRules(definition.XmlValueWhenDisabled);

        if (desiredXmlValue is not null)
        {
            GetOrCreateRules().Add(
                new XElement(
                    _namespace + "Rule",
                    new XElement(_namespace + "Option", desiredXmlValue)));
        }

        PolicyOptionState after = Snapshot.GetOption(change.OptionId);
        if (before.IsEnabled != after.IsEnabled || before.IsExplicit != after.IsExplicit)
        {
            changes.Add(
                new PolicySemanticChange(
                    "Policy option",
                    definition.DisplayName,
                    before.IsEnabled.ToString(CultureInfo.InvariantCulture),
                    after.IsEnabled.ToString(CultureInfo.InvariantCulture)));
        }
    }

    private void ApplyHvciChange(
        PolicyHvciChange change,
        ICollection<PolicySemanticChange> changes)
    {
        XElement root = _document.Root!;
        XElement? hvciElement = root.Element(_namespace + "HvciOptions");
        string before = hvciElement?.Value ?? "(not specified)";
        string after = change.Value.ToString(CultureInfo.InvariantCulture);
        if (string.Equals(before, after, StringComparison.Ordinal))
        {
            return;
        }

        if (hvciElement is null)
        {
            hvciElement = new XElement(_namespace + "HvciOptions", after);
            XElement? settings = root.Element(_namespace + "Settings");
            if (settings is null)
            {
                root.Add(hvciElement);
            }
            else
            {
                settings.AddBeforeSelf(hvciElement);
            }
        }
        else
        {
            hvciElement.Value = after;
        }

        changes.Add(new PolicySemanticChange("Device-wide runtime", "HVCI", before, after));
    }

    private void ApplySettingChange(
        PolicySettingChange change,
        ICollection<PolicySemanticChange> changes)
    {
        XElement settings = GetOrCreateSettings();
        List<XElement> existing = FindSettings(change.Key).ToList();
        string before = existing.Count == 0
            ? "(not specified)"
            : string.Join(", ", existing.Select(DescribeSetting));
        if (change.Values is { Count: not 1 })
        {
            throw new InvalidDataException(
                "App Control policy settings must contain exactly one typed value.");
        }

        string desired = change.Values is null
            ? "(removed)"
            : DescribeValues(change.Values);
        if (existing.Count == 1 && string.Equals(before, desired, StringComparison.Ordinal))
        {
            return;
        }

        foreach (XElement setting in existing)
        {
            setting.Remove();
        }

        string after = "(removed)";
        if (change.Values is not null)
        {
            XElement replacement = CreateSetting(change.Key, change.Values);
            settings.Add(replacement);
            after = desired;
        }

        if (!string.Equals(before, after, StringComparison.Ordinal))
        {
            changes.Add(
                new PolicySemanticChange(
                    "Platform behavior",
                    $"{change.Key.Provider}/{change.Key.Key}/{change.Key.ValueName}",
                    before,
                    after));
        }
    }

    private void RemoveOptionRules(string? xmlValue)
    {
        if (xmlValue is null)
        {
            return;
        }

        foreach (XElement rule in GetOptionRules(xmlValue).ToList())
        {
            rule.Remove();
        }
    }

    private IEnumerable<XElement> GetOptionRules(string xmlValue)
    {
        return _document.Root?
            .Element(_namespace + "Rules")?
            .Elements(_namespace + "Rule")
            .Where(rule => string.Equals(
                rule.Element(_namespace + "Option")?.Value,
                xmlValue,
                StringComparison.Ordinal))
            ?? [];
    }

    private XElement GetOrCreateRules()
    {
        XElement root = _document.Root!;
        XElement? rules = root.Element(_namespace + "Rules");
        if (rules is not null)
        {
            return rules;
        }

        rules = new XElement(_namespace + "Rules");
        XElement? platformId = root.Element(_namespace + "PlatformID");
        if (platformId is null)
        {
            root.AddFirst(rules);
        }
        else
        {
            platformId.AddAfterSelf(rules);
        }

        return rules;
    }

    private XElement GetOrCreateSettings()
    {
        XElement root = _document.Root!;
        XElement? settings = root.Element(_namespace + "Settings");
        if (settings is null)
        {
            settings = new XElement(_namespace + "Settings");
            root.Add(settings);
        }

        return settings;
    }

    private IEnumerable<XElement> FindSettings(PolicySettingKey key)
    {
        return _document.Root?
            .Element(_namespace + "Settings")?
            .Elements(_namespace + "Setting")
            .Where(setting =>
                string.Equals((string?)setting.Attribute("Provider"), key.Provider, StringComparison.Ordinal)
                && string.Equals((string?)setting.Attribute("Key"), key.Key, StringComparison.Ordinal)
                && string.Equals((string?)setting.Attribute("ValueName"), key.ValueName, StringComparison.Ordinal))
            ?? [];
    }

    private XElement CreateSetting(
        PolicySettingKey key,
        IReadOnlyList<PolicySettingValue> values)
    {
        return new XElement(
            _namespace + "Setting",
            new XAttribute("Provider", key.Provider),
            new XAttribute("Key", key.Key),
            new XAttribute("ValueName", key.ValueName),
            values.Select(value =>
                new XElement(
                    _namespace + "Value",
                    new XElement(_namespace + value.ElementName, value.Value))));
    }

    private string DescribeSetting(XElement setting)
    {
        return DescribeValues(
            setting
                .Elements(_namespace + "Value")
                .SelectMany(value => value.Elements())
                .Select(value => new PolicySettingValue(
                    GetSettingValueKind(value.Name.LocalName),
                    value.Value,
                    value.Name.LocalName))
                .ToList());
    }

    private static string DescribeValues(IReadOnlyList<PolicySettingValue> values)
    {
        return string.Join(
            ", ",
            values.Select(value => $"{value.ElementName}={value.Value}"));
    }

    private static PolicyConfigurationSnapshot CreateSnapshot(XDocument document)
    {
        XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
        XElement root = document.Root!;
        List<XElement> ruleElements = root
            .Element(policyNamespace + "Rules")?
            .Elements(policyNamespace + "Rule")
            .ToList()
            ?? [];
        var knownValues = new Dictionary<string, List<XElement>>(StringComparer.Ordinal);
        var unknownOptions = new List<UnknownPolicyOption>();

        foreach (XElement rule in ruleElements)
        {
            XElement? option = rule.Element(policyNamespace + "Option");
            if (option is null)
            {
                continue;
            }

            if (PolicyOptionCatalog.TryGetByXmlValue(option.Value, out _))
            {
                if (!knownValues.TryGetValue(option.Value, out List<XElement>? matches))
                {
                    matches = [];
                    knownValues.Add(option.Value, matches);
                }

                matches.Add(rule);
            }
            else
            {
                unknownOptions.Add(
                    new UnknownPolicyOption(
                        option.Value,
                        rule.ToString(SaveOptions.DisableFormatting)));
            }
        }

        var findings = new List<PolicyCompatibilityFinding>();
        var states = new List<PolicyOptionState>();
        foreach (PolicyOptionDefinition definition in PolicyOptionCatalog.Definitions)
        {
            int enabledCount = Count(definition.XmlValueWhenEnabled);
            int disabledCount = Count(definition.XmlValueWhenDisabled);
            bool isExplicit = enabledCount + disabledCount > 0;
            bool isEnabled = enabledCount > 0
                ? true
                : disabledCount > 0
                    ? false
                    : definition.ValueWhenAbsent;
            string? sourceValue = enabledCount > 0
                ? definition.XmlValueWhenEnabled
                : disabledCount > 0
                    ? definition.XmlValueWhenDisabled
                    : null;

            states.Add(new PolicyOptionState(definition, isEnabled, isExplicit, sourceValue));

            if (enabledCount > 0 && disabledCount > 0)
            {
                findings.Add(
                    new PolicyCompatibilityFinding(
                        "conflicting-option-values",
                        $"The policy contains conflicting representations for '{definition.DisplayName}'.",
                        sourceValue));
            }

            if (enabledCount + disabledCount > 1)
            {
                findings.Add(
                    new PolicyCompatibilityFinding(
                        "duplicate-option",
                        $"The policy contains duplicate entries for '{definition.DisplayName}'.",
                        sourceValue));
            }

            if (isExplicit && definition.Support != PolicyOptionSupport.Supported)
            {
                findings.Add(
                    new PolicyCompatibilityFinding(
                        definition.Support == PolicyOptionSupport.Reserved
                            ? "reserved-option"
                            : "unsupported-option",
                        $"The policy contains the {definition.Support.ToString().ToLowerInvariant()} option '{definition.DisplayName}'.",
                        sourceValue));
            }
        }

        XElement? hvciElement = root.Element(policyNamespace + "HvciOptions");
        uint? hvciOptions = uint.TryParse(
            hvciElement?.Value,
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out uint parsedHvci)
            ? parsedHvci
            : null;
        if (hvciElement is not null && hvciOptions is null)
        {
            findings.Add(
                new PolicyCompatibilityFinding(
                    "invalid-hvci-value",
                    $"The policy contains an invalid HVCI value '{hvciElement.Value}'."));
        }

        List<PolicySettingState> settings = root
            .Element(policyNamespace + "Settings")?
            .Elements(policyNamespace + "Setting")
            .Select(setting => ParseSetting(setting, policyNamespace))
            .ToList()
            ?? [];

        return new PolicyConfigurationSnapshot(
            ParsePolicyType((string?)root.Attribute("PolicyType")),
            states,
            unknownOptions,
            hvciOptions,
            hvciElement?.Value,
            settings,
            findings);

        int Count(string? xmlValue)
        {
            return xmlValue is not null && knownValues.TryGetValue(xmlValue, out List<XElement>? matches)
                ? matches.Count
                : 0;
        }

    }

    private static AppControlPolicyType ParsePolicyType(string? policyType)
    {
        return policyType switch
        {
            "Base Policy" => AppControlPolicyType.Base,
            "Supplemental Policy" => AppControlPolicyType.Supplemental,
            "AppID Tagging Policy" => AppControlPolicyType.AppIdTagging,
            _ => AppControlPolicyType.Unknown
        };
    }

    private static PolicySettingState ParseSetting(
        XElement setting,
        XNamespace policyNamespace)
    {
        var key = new PolicySettingKey(
            (string?)setting.Attribute("Provider") ?? string.Empty,
            (string?)setting.Attribute("Key") ?? string.Empty,
            (string?)setting.Attribute("ValueName") ?? string.Empty);
        List<PolicySettingValue> values = setting
            .Elements(policyNamespace + "Value")
            .SelectMany(value => value.Elements())
            .Select(value => new PolicySettingValue(
                GetSettingValueKind(value.Name.LocalName),
                value.Value,
                value.Name.LocalName))
            .ToList();

        return new PolicySettingState(
            key,
            values,
            setting.ToString(SaveOptions.DisableFormatting));
    }

    private static PolicySettingValueKind GetSettingValueKind(string elementName)
    {
        return elementName switch
        {
            "Boolean" => PolicySettingValueKind.Boolean,
            "DWord" => PolicySettingValueKind.DWord,
            "String" => PolicySettingValueKind.String,
            "Binary" => PolicySettingValueKind.Binary,
            _ => PolicySettingValueKind.Unknown
        };
    }
}
