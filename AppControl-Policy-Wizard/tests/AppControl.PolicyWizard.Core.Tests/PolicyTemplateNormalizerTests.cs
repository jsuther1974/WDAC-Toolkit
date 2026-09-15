using System.Xml.Linq;
using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Core.Tests;

public sealed class PolicyTemplateNormalizerTests
{
    [Theory]
    [InlineData("signed-reputable", "SignedReputable.xml")]
    [InlineData("windows-only", "DefaultWindows_Audit.xml")]
    public void NormalizerVerifiesSnapshotAndRemovesOnlyApprovedUnsupportedOptions(
        string templateId,
        string fileName)
    {
        using var testDirectory = new TestDirectory();
        string templatesPath = Path.Combine(AppContext.BaseDirectory, "Templates");
        string manifestPath = Path.Combine(templatesPath, "template-manifest.json");
        string sourcePath = Path.Combine(templatesPath, fileName);
        string outputPath = Path.Combine(testDirectory.Path, fileName);
        string sourceBefore = File.ReadAllText(sourcePath);
        PolicyTemplateManifest manifest = PolicyTemplateManifest.Load(manifestPath);

        PolicyTemplateNormalizationResult result = new PolicyTemplateNormalizer().Normalize(
            sourcePath,
            outputPath,
            manifest.GetTemplate(templateId));

        Assert.Equal(sourceBefore, File.ReadAllText(sourcePath));
        PolicyConfigurationSnapshot snapshot = PolicyConfigurationEditor.Open(outputPath).Snapshot;
        Assert.DoesNotContain(
            snapshot.Options,
            option => option.IsExplicit
                && option.Definition.Support != PolicyOptionSupport.Supported);
        PolicyTemplateNormalizationChange change = Assert.Single(result.Changes);
        Assert.Equal("Enabled:Inherit Default Policy", change.XmlValue);
        Assert.Equal(1, change.RemovedCount);

        XDocument source = XDocument.Load(sourcePath);
        XDocument output = XDocument.Load(outputPath);
        XNamespace ns = PolicyDocumentService.PolicyNamespace;
        string[] sourceOptions = GetOptions(source, ns)
            .Where(option => option != "Enabled:Inherit Default Policy")
            .ToArray();
        Assert.Equal(sourceOptions, GetOptions(output, ns));
    }

    [Fact]
    public void NormalizerRejectsAnUnrecordedSnapshotChange()
    {
        using var testDirectory = new TestDirectory();
        string sourcePath = testDirectory.WriteText(
            "Changed.xml",
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <VersionEx>1.0.0.0</VersionEx>
              <Rules />
            </SiPolicy>
            """);
        var definition = new PolicyTemplateDefinition
        {
            Id = "changed",
            FileName = "Changed.xml",
            Sha256 = new string('0', 64),
            Source = "test",
            SourceRevision = "test"
        };

        Assert.Throws<InvalidDataException>(
            () => new PolicyTemplateNormalizer().Normalize(
                sourcePath,
                Path.Combine(testDirectory.Path, "Output.xml"),
                definition));
    }

    private static IEnumerable<string> GetOptions(XDocument document, XNamespace ns)
    {
        return document.Root!
            .Element(ns + "Rules")!
            .Elements(ns + "Rule")
            .Select(rule => rule.Element(ns + "Option")?.Value)
            .Where(value => value is not null)
            .Select(value => value!);
    }
}
