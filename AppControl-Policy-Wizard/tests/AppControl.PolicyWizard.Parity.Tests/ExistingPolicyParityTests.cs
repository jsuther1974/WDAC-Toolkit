using System.Xml.Linq;
using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.Infrastructure.Windows;

namespace AppControl.PolicyWizard.Parity.Tests;

public sealed class ExistingPolicyParityTests
{
    [Fact]
    public async Task ExistingPolicyEditMatchesLegacyVersionAndIdentityBehavior()
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-parity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(testDirectory);

        try
        {
            string sourcePath = Path.Combine(
                AppContext.BaseDirectory,
                "SuccessorTemplates",
                "DefaultWindows_Audit.xml");
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
                    [PolicySourceKind.WindowsOnly] = sourcePath
                });
            PolicySourceInfo source = workflow.InspectExistingPolicy(sourcePath);
            string outputPath = Path.Combine(
                testDirectory,
                $"DefaultWindows_Audit_v{source.NextVersion}.xml");

            PolicyBuildResult result = await workflow.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.ExistingPolicy,
                    sourcePath,
                    source.PolicyName ?? "Windows only",
                    outputPath));

            XDocument original = XDocument.Load(sourcePath);
            XDocument edited = XDocument.Load(result.XmlPath);
            XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;

            Assert.Equal(source.PolicyID, result.PolicyID, ignoreCase: true);
            Assert.Equal(source.BasePolicyID, result.BasePolicyID, ignoreCase: true);
            Assert.Equal(PolicyVersion.Increment(source.Version), result.Version);
            Assert.True(XNode.DeepEquals(
                original.Root!.Element(policyNamespace + "Rules"),
                edited.Root!.Element(policyNamespace + "Rules")));
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
