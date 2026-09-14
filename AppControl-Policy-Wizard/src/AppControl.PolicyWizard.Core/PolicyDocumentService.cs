using System.Xml;
using System.Xml.Linq;

namespace AppControl.PolicyWizard.Core;

public sealed class PolicyDocumentService
{
    public const string PolicyNamespace = "urn:schemas-microsoft-com:sipolicy";

    public PolicySourceInfo InspectExistingPolicy(string policyPath)
    {
        string fullPath = Path.GetFullPath(policyPath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("The selected policy file could not be found.", fullPath);
        }

        if (!string.Equals(Path.GetExtension(fullPath), ".xml", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Select an App Control policy with the .xml extension.");
        }

        XDocument document = Load(fullPath);
        XNamespace policyNamespace = PolicyNamespace;
        XElement root = document.Root!;
        string version = root.Element(policyNamespace + "VersionEx")?.Value
            ?? throw new InvalidDataException(
                "The selected policy does not specify a VersionEx value.");

        string? policyName = root
            .Element(policyNamespace + "Settings")?
            .Elements(policyNamespace + "Setting")
            .FirstOrDefault(setting =>
                string.Equals((string?)setting.Attribute("Provider"), "PolicyInfo", StringComparison.Ordinal)
                && string.Equals((string?)setting.Attribute("Key"), "Information", StringComparison.Ordinal)
                && string.Equals((string?)setting.Attribute("ValueName"), "Name", StringComparison.Ordinal))?
            .Descendants(policyNamespace + "String")
            .FirstOrDefault()?
            .Value;

        return new PolicySourceInfo(
            fullPath,
            root.Element(policyNamespace + "PolicyID")?.Value,
            root.Element(policyNamespace + "BasePolicyID")?.Value,
            version,
            PolicyVersion.Increment(version),
            policyName);
    }

    public XDocument Load(string policyPath)
    {
        try
        {
            XDocument document = XDocument.Load(policyPath, LoadOptions.PreserveWhitespace);
            XName expectedRoot = XName.Get("SiPolicy", PolicyNamespace);
            if (document.Root?.Name != expectedRoot)
            {
                throw new InvalidDataException(
                    $"The file '{Path.GetFileName(policyPath)}' is not a valid App Control policy.");
            }

            return document;
        }
        catch (XmlException exception)
        {
            throw new InvalidDataException(
                $"The policy '{Path.GetFileName(policyPath)}' contains invalid XML.",
                exception);
        }
    }
}
