using System.Xml.Linq;
using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.Infrastructure.Windows;

namespace AppControl.PolicyWizard.Parity.Tests;

public sealed class EditedTemplateParityTests
{
    [Fact]
    public async Task DriverOnlyBehaviorDeltaCompilesWithConfigCi()
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-edited-template-{Guid.NewGuid():N}");
        Directory.CreateDirectory(testDirectory);

        try
        {
            string templatesPath = Path.Combine(
                AppContext.BaseDirectory,
                "SuccessorTemplates");
            string signedReputablePath = Path.Combine(
                templatesPath,
                "SignedReputable.xml");
            var workflow = new PolicyWorkflowService(
                new PowerShellConfigCiCompiler(
                    Path.Combine(
                        AppContext.BaseDirectory,
                        "Scripts",
                        "CreateBasePolicy.ps1")),
                new Dictionary<PolicySourceKind, string>
                {
                    [PolicySourceKind.SignedAndReputable] = signedReputablePath,
                    [PolicySourceKind.WindowsOnly] = Path.Combine(
                        templatesPath,
                        "DefaultWindows_Audit.xml")
                },
                templateManifest: PolicyTemplateManifest.Load(
                    Path.Combine(templatesPath, "template-manifest.json")));
            PolicyConfigurationEditor configuration =
                workflow.OpenPolicyConfiguration(
                    PolicySourceKind.SignedAndReputable);
            PolicyBehaviorSelection source =
                PolicyBehaviorSelection.FromSnapshot(configuration.Snapshot);
            configuration.Apply(
                (source with
                {
                    UserModeCodeIntegrity = false,
                    MicrosoftCloudReputation = false,
                    ManagedInstaller = false,
                    DynamicCodeSecurity = false,
                    EnforceStoreApplications = false,
                    RevokedExpiredAsUnsigned = false
                }).ToDelta());
            string outputPath = Path.Combine(testDirectory, "DriverOnly.xml");

            PolicyBuildResult result = await workflow.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.SignedAndReputable,
                    ExistingPolicyPath: null,
                    "Driver only",
                    outputPath,
                    configuration));

            XDocument output = XDocument.Load(result.XmlPath);
            XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
            string[] options = output.Root!
                .Element(policyNamespace + "Rules")!
                .Elements(policyNamespace + "Rule")
                .Select(rule => rule.Element(policyNamespace + "Option")?.Value)
                .Where(value => value is not null)
                .Select(value => value!)
                .ToArray();
            Assert.DoesNotContain("Enabled:UMCI", options);
            Assert.DoesNotContain(
                "Enabled:Intelligent Security Graph Authorization",
                options);
            Assert.DoesNotContain(
                "Enabled:Developer Mode Dynamic Code Trust",
                options);
            Assert.DoesNotContain("Enabled:Revoked Expired As Unsigned", options);
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
