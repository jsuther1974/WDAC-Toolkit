using System.Xml.Linq;
using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.Infrastructure.Windows;

namespace AppControl.PolicyWizard.Parity.Tests;

public sealed class ApplicationRuleParityTests
{
    [Fact]
    public async Task StagedHashRuleCompilesWithConfigCi()
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-rule-template-{Guid.NewGuid():N}");
        Directory.CreateDirectory(testDirectory);

        try
        {
            string templatesPath = Path.Combine(
                AppContext.BaseDirectory,
                "SuccessorTemplates");
            var workflow = new PolicyWorkflowService(
                new PowerShellConfigCiCompiler(
                    Path.Combine(
                        AppContext.BaseDirectory,
                        "Scripts",
                        "CreateBasePolicy.ps1")),
                new Dictionary<PolicySourceKind, string>
                {
                    [PolicySourceKind.SignedAndReputable] = Path.Combine(
                        templatesPath,
                        "SignedReputable.xml"),
                    [PolicySourceKind.WindowsOnly] = Path.Combine(
                        templatesPath,
                        "DefaultWindows_Audit.xml")
                },
                templateManifest: PolicyTemplateManifest.Load(
                    Path.Combine(templatesPath, "template-manifest.json")));
            PolicyConfigurationEditor configuration =
                workflow.OpenPolicyConfiguration(
                    PolicySourceKind.SignedAndReputable);
            const string hash =
                "579A240282175C8D78CE9CCFA29ACD0212BB43A5AEE769DE74D6CB313345791C";
            var candidate = new PolicyRuleCandidate(
                "parity-hash",
                PolicyRuleAction.Allow,
                PolicyRuleIdentity.Hash,
                PolicyRuleScenario.Applications,
                "Contoso exact binary",
                $"Match SHA-256 {hash}",
                "Parity evidence",
                new Dictionary<string, string> { ["Hash"] = hash },
                RuleTrustBreadth.ExactArtifact,
                RuleUpdateResilience.Low,
                RuleEvidenceQuality.Verified,
                ["The rule must be replaced whenever the file content changes."],
                CanApply: true);
            configuration.ApplyRules([new PolicyRuleAddition(candidate)]);
            string outputPath = Path.Combine(testDirectory, "RulePolicy.xml");

            PolicyBuildResult result = await workflow.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.SignedAndReputable,
                    ExistingPolicyPath: null,
                    "Application rule parity",
                    outputPath,
                    configuration));

            XDocument output = XDocument.Load(result.XmlPath);
            XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
            XElement addedRule = Assert.Single(
                output.Root!
                    .Element(policyNamespace + "FileRules")!
                    .Elements(policyNamespace + "Allow"),
                rule => rule.Attribute("Hash")?.Value == hash);
            Assert.Contains(
                output.Root
                    .Element(policyNamespace + "SigningScenarios")!
                    .Elements(policyNamespace + "SigningScenario")
                    .Single(scenario => scenario.Attribute("Value")?.Value == "12")
                    .Descendants(policyNamespace + "FileRuleRef"),
                reference => reference.Attribute("RuleID")?.Value
                    == addedRule.Attribute("ID")?.Value);
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
