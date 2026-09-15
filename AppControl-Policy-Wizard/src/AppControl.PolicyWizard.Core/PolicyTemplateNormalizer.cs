using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;

namespace AppControl.PolicyWizard.Core;

public enum PolicyTemplateNormalizationAction
{
    RemovePolicyOption
}

public sealed class PolicyTemplateManifest
{
    public int SchemaVersion { get; init; }

    public List<PolicyTemplateDefinition> Templates { get; init; } = [];

    public static PolicyTemplateManifest Load(string manifestPath)
    {
        string json = File.ReadAllText(manifestPath);
        return JsonSerializer.Deserialize<PolicyTemplateManifest>(
            json,
            new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
            })
            ?? throw new InvalidDataException("The policy template manifest is empty.");
    }

    public PolicyTemplateDefinition GetTemplate(string templateId)
    {
        return Templates.Single(template =>
            string.Equals(template.Id, templateId, StringComparison.Ordinal));
    }
}

public sealed class PolicyTemplateDefinition
{
    public required string Id { get; init; }

    public required string FileName { get; init; }

    public required string Sha256 { get; init; }

    public required string Source { get; init; }

    public required string SourceRevision { get; init; }

    public List<PolicyTemplateNormalizationOperation> Normalization { get; init; } = [];
}

public sealed class PolicyTemplateNormalizationOperation
{
    public PolicyTemplateNormalizationAction Action { get; init; }

    public required string XmlValue { get; init; }

    public required string Reason { get; init; }

    public bool Required { get; init; } = true;
}

public sealed record PolicyTemplateNormalizationChange(
    string XmlValue,
    int RemovedCount,
    string Reason);

public sealed record PolicyTemplateNormalizationResult(
    string OutputPath,
    IReadOnlyList<PolicyTemplateNormalizationChange> Changes);

public sealed record PolicyTemplateNormalizationDocumentResult(
    XDocument Document,
    IReadOnlyList<PolicyTemplateNormalizationChange> Changes);

public sealed class PolicyTemplateNormalizer
{
    public PolicyTemplateNormalizationResult Normalize(
        string sourcePath,
        string outputPath,
        PolicyTemplateDefinition definition)
    {
        PolicyTemplateNormalizationDocumentResult normalized =
            NormalizeToDocument(sourcePath, definition);
        string fullOutputPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(
            Path.GetDirectoryName(fullOutputPath)
            ?? throw new InvalidOperationException("The output path has no parent directory."));
        normalized.Document.Save(fullOutputPath, SaveOptions.DisableFormatting);

        return new PolicyTemplateNormalizationResult(fullOutputPath, normalized.Changes);
    }

    public PolicyTemplateNormalizationDocumentResult NormalizeToDocument(
        string sourcePath,
        PolicyTemplateDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        string fullSourcePath = Path.GetFullPath(sourcePath);
        string sourceText = File.ReadAllText(fullSourcePath)
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\r", "\n", StringComparison.Ordinal);
        string actualHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(sourceText)));
        if (!string.Equals(actualHash, definition.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Template '{definition.Id}' does not match its recorded upstream SHA-256 hash.");
        }

        XDocument document = new PolicyDocumentService().Load(fullSourcePath);
        XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
        var changes = new List<PolicyTemplateNormalizationChange>();

        foreach (PolicyTemplateNormalizationOperation operation in definition.Normalization)
        {
            if (operation.Action != PolicyTemplateNormalizationAction.RemovePolicyOption)
            {
                throw new InvalidDataException(
                    $"Template '{definition.Id}' contains an unsupported normalization action.");
            }

            List<XElement> rules = document.Root?
                .Element(policyNamespace + "Rules")?
                .Elements(policyNamespace + "Rule")
                .Where(rule => string.Equals(
                    rule.Element(policyNamespace + "Option")?.Value,
                    operation.XmlValue,
                    StringComparison.Ordinal))
                .ToList()
                ?? [];

            if (operation.Required && rules.Count == 0)
            {
                throw new InvalidDataException(
                    $"Template '{definition.Id}' no longer contains the expected option '{operation.XmlValue}'.");
            }

            foreach (XElement rule in rules)
            {
                rule.Remove();
            }

            changes.Add(
                new PolicyTemplateNormalizationChange(
                    operation.XmlValue,
                    rules.Count,
                    operation.Reason));
        }

        PolicyConfigurationSnapshot normalized =
            PolicyConfigurationEditor.FromDocument(document).Snapshot;
        PolicyOptionState? remainingUnsupported = normalized.Options.FirstOrDefault(
            state => state.IsExplicit
                && state.Definition.Support != PolicyOptionSupport.Supported);
        if (remainingUnsupported is not null)
        {
            throw new InvalidDataException(
                $"Template '{definition.Id}' contains the unapproved {remainingUnsupported.Definition.Support.ToString().ToLowerInvariant()} option '{remainingUnsupported.SourceXmlValue}'.");
        }

        return new PolicyTemplateNormalizationDocumentResult(document, changes);
    }
}
