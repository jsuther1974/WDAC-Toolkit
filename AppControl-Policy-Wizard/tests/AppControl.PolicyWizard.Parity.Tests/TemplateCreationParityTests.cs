using System.Xml.Linq;
using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.Infrastructure.Windows;

namespace AppControl.PolicyWizard.Parity.Tests;

public sealed class TemplateCreationParityTests
{
    [Fact]
    public async Task NormalizedSignedReputableTemplateCompilesWithConfigCi()
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-template-parity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(testDirectory);

        try
        {
            string templatesPath = Path.Combine(
                AppContext.BaseDirectory,
                "SuccessorTemplates");
            string sourcePath = Path.Combine(templatesPath, "SignedReputable.xml");
            PolicyTemplateManifest manifest = PolicyTemplateManifest.Load(
                Path.Combine(templatesPath, "template-manifest.json"));
            var compiler = new PowerShellConfigCiCompiler(
                Path.Combine(
                    AppContext.BaseDirectory,
                    "Scripts",
                    "CreateBasePolicy.ps1"));
            var workflow = new PolicyWorkflowService(
                compiler,
                new Dictionary<PolicySourceKind, string>
                {
                    [PolicySourceKind.SignedAndReputable] = sourcePath,
                    [PolicySourceKind.WindowsOnly] = Path.Combine(
                        templatesPath,
                        "DefaultWindows_Audit.xml")
                },
                templateManifest: manifest);
            string outputPath = Path.Combine(testDirectory, "SignedReputable.xml");

            PolicyBuildResult result = await workflow.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.SignedAndReputable,
                    ExistingPolicyPath: null,
                    "Signed and reputable",
                    outputPath));

            XDocument source = XDocument.Load(sourcePath);
            XDocument output = XDocument.Load(result.XmlPath);
            XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
            string[] outputOptions = output.Root!
                .Element(policyNamespace + "Rules")!
                .Elements(policyNamespace + "Rule")
                .Select(rule => rule.Element(policyNamespace + "Option")?.Value)
                .Where(value => value is not null)
                .Select(value => value!)
                .ToArray();

            Assert.Contains(
                "Enabled:Inherit Default Policy",
                source.Root!
                    .Element(policyNamespace + "Rules")!
                    .Elements(policyNamespace + "Rule")
                    .Select(rule => rule.Element(policyNamespace + "Option")?.Value));
            Assert.DoesNotContain("Enabled:Inherit Default Policy", outputOptions);
            Assert.Contains("Enabled:Developer Mode Dynamic Code Trust", outputOptions);
            Assert.Equal(PolicyWorkflowService.InitialPolicyVersion, result.Version);
            Assert.False(string.IsNullOrWhiteSpace(result.PolicyID));
            Assert.Equal(result.PolicyID, result.BasePolicyID, ignoreCase: true);
            Assert.True(File.Exists(result.BinaryPath));
        }
        finally
        {
            if (Directory.Exists(testDirectory))
            {
                Directory.Delete(testDirectory, recursive: true);
            }
        }
    }
}
