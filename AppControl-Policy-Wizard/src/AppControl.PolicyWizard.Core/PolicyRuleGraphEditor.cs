using System.Xml.Linq;

namespace AppControl.PolicyWizard.Core;

public sealed class PolicyRuleGraphEditor
{
    private readonly XDocument _document;
    private readonly XNamespace _namespace = PolicyDocumentService.PolicyNamespace;

    private PolicyRuleGraphEditor(XDocument document)
    {
        _document = document;
    }

    public PolicyRuleGraphSnapshot Snapshot => CreateSnapshot(_document);

    public static PolicyRuleGraphEditor FromDocument(XDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        XName expectedRoot = XName.Get("SiPolicy", PolicyDocumentService.PolicyNamespace);
        if (document.Root?.Name != expectedRoot)
        {
            throw new InvalidDataException("The document is not a valid App Control policy.");
        }

        return new PolicyRuleGraphEditor(new XDocument(document));
    }

    public PolicyRuleChangeResult Apply(IEnumerable<PolicyRuleAddition> additions)
    {
        ArgumentNullException.ThrowIfNull(additions);
        var changes = new List<PolicySemanticChange>();

        foreach (PolicyRuleAddition addition in additions)
        {
            AddCandidate(addition.Candidate, changes);
        }

        return new PolicyRuleChangeResult(Snapshot, changes);
    }

    public XDocument ToDocument()
    {
        return new XDocument(_document);
    }

    private void AddCandidate(
        PolicyRuleCandidate candidate,
        ICollection<PolicySemanticChange> changes)
    {
        if (!candidate.CanApply)
        {
            throw new InvalidOperationException(
                candidate.UnavailableReason
                ?? $"The {candidate.Identity} candidate cannot be applied.");
        }

        if (Snapshot.FindEquivalent(candidate) is not null)
        {
            return;
        }

        XElement rule = candidate.Identity switch
        {
            PolicyRuleIdentity.FilePath => CreateFilePathRule(candidate),
            PolicyRuleIdentity.FileName => CreateFileNameRule(candidate),
            PolicyRuleIdentity.Hash => CreateHashRule(candidate),
            _ => throw new InvalidOperationException(
                $"Rule identity '{candidate.Identity}' is not materialized by this release.")
        };

        GetOrCreateFileRules().Add(rule);
        AddScenarioReferences(
            rule.Attribute("ID")!.Value,
            candidate.Action,
            candidate.Scenario);
        changes.Add(new PolicySemanticChange(
            "Application rule",
            candidate.Title,
            "Not present",
            candidate.Effect));
    }

    private XElement CreateFilePathRule(PolicyRuleCandidate candidate)
    {
        string path = RequireCondition(candidate, "FilePath");
        return CreateRuleElement(
            candidate,
            new XAttribute("FilePath", path));
    }

    private XElement CreateFileNameRule(PolicyRuleCandidate candidate)
    {
        var attributes = new List<XAttribute>
        {
            new("FileName", RequireCondition(candidate, "FileName"))
        };
        AddOptionalAttribute(attributes, candidate, "MinimumFileVersion");
        AddOptionalAttribute(attributes, candidate, "InternalName");
        AddOptionalAttribute(attributes, candidate, "ProductName");
        AddOptionalAttribute(attributes, candidate, "FileDescription");
        return CreateRuleElement(candidate, attributes.ToArray());
    }

    private XElement CreateHashRule(PolicyRuleCandidate candidate)
    {
        string hash = RequireCondition(candidate, "Hash");
        return CreateRuleElement(
            candidate,
            new XAttribute("Hash", hash));
    }

    private XElement CreateRuleElement(
        PolicyRuleCandidate candidate,
        params XAttribute[] conditions)
    {
        string prefix = candidate.Action == PolicyRuleAction.Allow
            ? "ID_ALLOW"
            : "ID_DENY";
        string id = $"{prefix}_PW_{Guid.NewGuid():N}".ToUpperInvariant();
        var attributes = new List<object>
        {
            new XAttribute("ID", id),
            new XAttribute("FriendlyName", candidate.Effect)
        };
        attributes.AddRange(conditions);
        return new XElement(
            _namespace + candidate.Action.ToString(),
            attributes.ToArray());
    }

    private void AddScenarioReferences(
        string ruleId,
        PolicyRuleAction action,
        PolicyRuleScenario scenario)
    {
        IEnumerable<string> values = scenario switch
        {
            PolicyRuleScenario.Applications => ["12"],
            PolicyRuleScenario.Drivers => ["131"],
            _ => ["12", "131"]
        };

        foreach (string value in values)
        {
            XElement signingScenario = GetOrCreateSigningScenario(value);
            XElement productSigners = GetOrCreateChild(signingScenario, "ProductSigners");
            XElement fileRulesRef = GetOrCreateChild(productSigners, "FileRulesRef");
            if (!fileRulesRef.Elements(_namespace + "FileRuleRef").Any(reference =>
                    string.Equals(
                        reference.Attribute("RuleID")?.Value,
                        ruleId,
                        StringComparison.Ordinal)))
            {
                fileRulesRef.Add(
                    new XElement(
                        _namespace + "FileRuleRef",
                        new XAttribute("RuleID", ruleId)));
            }
        }
    }

    private XElement GetOrCreateSigningScenario(string value)
    {
        XElement scenarios = GetOrCreateRootChild("SigningScenarios");
        XElement? existing = scenarios.Elements(_namespace + "SigningScenario")
            .FirstOrDefault(scenario => scenario.Attribute("Value")?.Value == value);
        if (existing is not null)
        {
            return existing;
        }

        string suffix = value == "12" ? "UMCI" : "KMCI";
        var created = new XElement(
            _namespace + "SigningScenario",
            new XAttribute("Value", value),
            new XAttribute("ID", $"ID_SIGNINGSCENARIO_{suffix}"),
            new XAttribute(
                "FriendlyName",
                value == "12"
                    ? "User Mode Signing Scenario"
                    : "Kernel Mode Signing Scenario"));
        scenarios.Add(created);
        return created;
    }

    private XElement GetOrCreateFileRules()
    {
        return GetOrCreateRootChild("FileRules");
    }

    private XElement GetOrCreateRootChild(string localName)
    {
        XElement root = _document.Root!;
        XElement? existing = root.Element(_namespace + localName);
        if (existing is not null)
        {
            return existing;
        }

        var created = new XElement(_namespace + localName);
        XElement? insertionPoint = localName switch
        {
            "FileRules" => root.Element(_namespace + "Signers"),
            "SigningScenarios" => root.Element(_namespace + "UpdatePolicySigners"),
            _ => null
        };
        if (insertionPoint is null)
        {
            root.Add(created);
        }
        else
        {
            insertionPoint.AddBeforeSelf(created);
        }

        return created;
    }

    private XElement GetOrCreateChild(XElement parent, string localName)
    {
        XElement? existing = parent.Element(_namespace + localName);
        if (existing is not null)
        {
            return existing;
        }

        var created = new XElement(_namespace + localName);
        parent.Add(created);
        return created;
    }

    private static string RequireCondition(
        PolicyRuleCandidate candidate,
        string name)
    {
        return candidate.Conditions.TryGetValue(name, out string? value)
            && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException(
                $"The candidate does not contain a required {name} condition.");
    }

    private static void AddOptionalAttribute(
        ICollection<XAttribute> attributes,
        PolicyRuleCandidate candidate,
        string name)
    {
        if (candidate.Conditions.TryGetValue(name, out string? value)
            && !string.IsNullOrWhiteSpace(value))
        {
            attributes.Add(new XAttribute(name, value));
        }
    }

    private static PolicyRuleGraphSnapshot CreateSnapshot(XDocument document)
    {
        XNamespace ns = PolicyDocumentService.PolicyNamespace;
        XElement? root = document.Root;
        if (root is null)
        {
            return new PolicyRuleGraphSnapshot([], []);
        }

        var scenarioByRule = new Dictionary<string, HashSet<string>>(
            StringComparer.Ordinal);
        var signerUsages = new Dictionary<string, List<SignerUsage>>(
            StringComparer.Ordinal);
        var exceptionRuleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (XElement scenario in root
                     .Element(ns + "SigningScenarios")?
                     .Elements(ns + "SigningScenario")
                 ?? [])
        {
            string? scenarioValue = scenario.Attribute("Value")?.Value;
            foreach (XElement reference in scenario.Descendants(ns + "FileRuleRef"))
            {
                string? ruleId = reference.Attribute("RuleID")?.Value;
                if (ruleId is null || scenarioValue is null)
                {
                    continue;
                }

                if (!scenarioByRule.TryGetValue(ruleId, out HashSet<string>? values))
                {
                    values = new HashSet<string>(StringComparer.Ordinal);
                    scenarioByRule.Add(ruleId, values);
                }

                values.Add(scenarioValue);
            }

            XElement? productSigners = scenario.Element(ns + "ProductSigners");
            AddSignerUsages(
                productSigners?
                    .Element(ns + "AllowedSigners")?
                    .Elements(ns + "AllowedSigner")
                    ?? [],
                PolicyRuleAction.Allow,
                scenarioValue,
                ns,
                signerUsages,
                exceptionRuleIds);
            AddSignerUsages(
                productSigners?
                    .Element(ns + "DeniedSigners")?
                    .Elements(ns + "DeniedSigner")
                    ?? [],
                PolicyRuleAction.Deny,
                scenarioValue,
                ns,
                signerUsages,
                exceptionRuleIds);
        }

        var logicalRules = new List<PolicyLogicalRule>();
        var unknownObjectIds = new List<string>();
        var fileRulesById = root.Element(ns + "FileRules")?
            .Elements()
            .Where(element => !string.IsNullOrWhiteSpace(element.Attribute("ID")?.Value))
            .ToDictionary(
                element => element.Attribute("ID")!.Value,
                element => element,
                StringComparer.Ordinal)
            ?? new Dictionary<string, XElement>(StringComparer.Ordinal);
        var referencedAttributeIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (XElement element in root.Element(ns + "FileRules")?.Elements() ?? [])
        {
            string? id = element.Attribute("ID")?.Value;
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            if (element.Name == ns + "FileAttrib")
            {
                continue;
            }

            if (element.Name != ns + "Allow" && element.Name != ns + "Deny")
            {
                unknownObjectIds.Add(id);
                continue;
            }

            if (exceptionRuleIds.Contains(id))
            {
                continue;
            }

            PolicyRuleIdentity identity = GetIdentity(element);
            IReadOnlyDictionary<string, string> conditions = element.Attributes()
                .Where(attribute => attribute.Name.LocalName is not "ID"
                    and not "FriendlyName")
                .ToDictionary(
                    attribute => attribute.Name.LocalName,
                    attribute => attribute.Value,
                    StringComparer.Ordinal);
            logicalRules.Add(new PolicyLogicalRule(
                id,
                element.Name.LocalName == "Allow"
                    ? PolicyRuleAction.Allow
                    : PolicyRuleAction.Deny,
                identity,
                element.Attribute("FriendlyName")?.Value ?? id,
                GetScenario(scenarioByRule.GetValueOrDefault(id)),
                conditions,
                [id],
                [],
                identity != PolicyRuleIdentity.Unknown));
        }

        foreach (XElement signer in root.Element(ns + "Signers")?.Elements(ns + "Signer")
                 ?? [])
        {
            string? id = signer.Attribute("ID")?.Value;
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            if (!signerUsages.TryGetValue(id, out List<SignerUsage>? usages)
                || usages.Count == 0)
            {
                unknownObjectIds.Add(id);
                continue;
            }

            foreach (IGrouping<PolicyRuleAction, SignerUsage> actionUsages in usages
                         .GroupBy(usage => usage.Action))
            {
                var conditions = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (XElement condition in signer.Elements())
                {
                    string? value = condition.Attribute("Value")?.Value
                        ?? condition.Attribute("ID")?.Value;
                    AddCondition(conditions, condition.Name.LocalName, value);
                }

                string[] attributeIds = signer.Elements(ns + "FileAttribRef")
                    .Select(reference => reference.Attribute("RuleID")?.Value)
                    .Where(value => value is not null)
                    .Cast<string>()
                    .ToArray();
                foreach (string attributeId in attributeIds)
                {
                    referencedAttributeIds.Add(attributeId);
                    if (!fileRulesById.TryGetValue(attributeId, out XElement? attribute))
                    {
                        continue;
                    }

                    foreach (XAttribute value in attribute.Attributes()
                                 .Where(value => value.Name.LocalName is not "ID"
                                     and not "FriendlyName"))
                    {
                        conditions[$"FileAttribute:{attributeId}:{value.Name.LocalName}"] =
                            value.Value;
                    }
                }

                logicalRules.Add(new PolicyLogicalRule(
                    usages.Select(usage => usage.Action).Distinct().Count() > 1
                        ? $"{id}:{actionUsages.Key}"
                        : id,
                    actionUsages.Key,
                    attributeIds.Length > 0
                        ? PolicyRuleIdentity.FilePublisher
                        : PolicyRuleIdentity.Signer,
                    signer.Attribute("Name")?.Value ?? id,
                    GetScenario(actionUsages.Select(usage => usage.ScenarioValue)),
                    conditions,
                    [id, .. attributeIds],
                    actionUsages
                        .SelectMany(usage => usage.ExceptionRuleIds)
                        .Distinct(StringComparer.Ordinal)
                        .ToArray(),
                    true));
            }
        }

        foreach (string attributeId in fileRulesById
                     .Where(pair => pair.Value.Name == ns + "FileAttrib")
                     .Select(pair => pair.Key)
                     .Where(attributeId => !referencedAttributeIds.Contains(attributeId)))
        {
            unknownObjectIds.Add(attributeId);
        }

        return new PolicyRuleGraphSnapshot(logicalRules, unknownObjectIds);
    }

    private static void AddSignerUsages(
        IEnumerable<XElement> references,
        PolicyRuleAction action,
        string? scenarioValue,
        XNamespace policyNamespace,
        IDictionary<string, List<SignerUsage>> usagesBySigner,
        ISet<string> exceptionRuleIds)
    {
        if (scenarioValue is null)
        {
            return;
        }

        foreach (XElement reference in references)
        {
            string? signerId = reference.Attribute("SignerId")?.Value;
            if (string.IsNullOrWhiteSpace(signerId))
            {
                continue;
            }

            string exceptionElementName = action == PolicyRuleAction.Allow
                ? "ExceptDenyRule"
                : "ExceptAllowRule";
            string exceptionAttributeName = action == PolicyRuleAction.Allow
                ? "DenyRuleID"
                : "AllowRuleID";
            string[] exceptions = reference.Elements(
                    policyNamespace + exceptionElementName)
                .Select(element => element.Attribute(exceptionAttributeName)?.Value)
                .Where(value => value is not null)
                .Cast<string>()
                .ToArray();
            foreach (string exceptionId in exceptions)
            {
                exceptionRuleIds.Add(exceptionId);
            }

            if (!usagesBySigner.TryGetValue(
                    signerId,
                    out List<SignerUsage>? usages))
            {
                usages = [];
                usagesBySigner.Add(signerId, usages);
            }

            usages.Add(new SignerUsage(action, scenarioValue, exceptions));
        }
    }

    private static void AddCondition(
        IDictionary<string, string> conditions,
        string name,
        string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        string key = name;
        int suffix = 2;
        while (conditions.ContainsKey(key))
        {
            key = $"{name}[{suffix++}]";
        }

        conditions.Add(key, value);
    }

    private static PolicyRuleIdentity GetIdentity(XElement element)
    {
        if (element.Attribute("Hash") is not null)
        {
            return PolicyRuleIdentity.Hash;
        }

        if (element.Attribute("FilePath") is not null)
        {
            return PolicyRuleIdentity.FilePath;
        }

        if (element.Attribute("FileName") is not null
            || element.Attribute("InternalName") is not null
            || element.Attribute("ProductName") is not null
            || element.Attribute("FileDescription") is not null)
        {
            return PolicyRuleIdentity.FileName;
        }

        return PolicyRuleIdentity.Unknown;
    }

    private static PolicyRuleScenario GetScenario(IEnumerable<string>? values)
    {
        string[] scenarioValues = values?.Distinct(StringComparer.Ordinal).ToArray()
            ?? [];
        bool applications = scenarioValues.Contains("12", StringComparer.Ordinal);
        bool drivers = scenarioValues.Contains("131", StringComparer.Ordinal);
        return (applications, drivers) switch
        {
            (true, true) => PolicyRuleScenario.ApplicationsAndDrivers,
            (false, true) => PolicyRuleScenario.Drivers,
            (true, false) => PolicyRuleScenario.Applications,
            _ => PolicyRuleScenario.Unassigned
        };
    }

    private sealed record SignerUsage(
        PolicyRuleAction Action,
        string ScenarioValue,
        IReadOnlyList<string> ExceptionRuleIds);
}
