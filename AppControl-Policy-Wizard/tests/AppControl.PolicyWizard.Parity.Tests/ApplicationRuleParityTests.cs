using System.Xml.Linq;
using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.Infrastructure.Windows;

namespace AppControl.PolicyWizard.Parity.Tests;

public sealed class ApplicationRuleParityTests
{
    [Theory]
    [InlineData(SignerRuleLevel.FilePublisher, PolicyRuleIdentity.FilePublisher)]
    [InlineData(SignerRuleLevel.Publisher, PolicyRuleIdentity.Publisher)]
    [InlineData(SignerRuleLevel.PcaCertificate, PolicyRuleIdentity.PcaCertificate)]
    public async Task GeneratedSignerRuleCompilesWithConfigCi(
        SignerRuleLevel level,
        PolicyRuleIdentity expectedIdentity)
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-signer-parity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(testDirectory);

        try
        {
            string templatesPath = Path.Combine(
                AppContext.BaseDirectory,
                "SuccessorTemplates");
            var workflow = CreateWorkflow(templatesPath);
            PolicyConfigurationEditor configuration =
                workflow.OpenPolicyConfiguration(
                    PolicySourceKind.SignedAndReputable);
            string evidencePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32",
                "notepad.exe");
            var generator = new PowerShellSignerRuleGenerator(
                Path.Combine(
                    AppContext.BaseDirectory,
                    "Scripts",
                    "CreateSignerRule.ps1"));

            SignerRuleGenerationResult generated =
                await generator.GenerateAsync(
                    new SignerRuleGenerationRequest(
                        evidencePath,
                        level,
                        PolicyRuleAction.Allow));
            PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
                evidencePath,
                PolicyRuleScenario.Applications,
                generated,
                configuration.RuleGraph);

            Assert.True(candidate.CanApply, candidate.UnavailableReason);
            Assert.Equal(expectedIdentity, candidate.Identity);
            configuration.ApplyRules([new PolicyRuleAddition(candidate)]);
            Assert.NotNull(configuration.RuleGraph.FindEquivalent(candidate));
            string outputPath = Path.Combine(
                testDirectory,
                $"{level}.xml");

            PolicyBuildResult result = await workflow.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.SignedAndReputable,
                    ExistingPolicyPath: null,
                    $"{level} signer parity",
                    outputPath,
                    configuration));

            XDocument output = XDocument.Load(result.XmlPath);
            XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
            Assert.Contains(
                output.Root!
                    .Element(policyNamespace + "Signers")!
                    .Elements(policyNamespace + "Signer"),
                signer => signer.Attribute("Name")?.Value
                    .Contains("Microsoft", StringComparison.OrdinalIgnoreCase)
                    == true);
            Assert.Contains(
                output.Root
                    .Element(policyNamespace + "SigningScenarios")!
                    .Elements(policyNamespace + "SigningScenario")
                    .Single(scenario =>
                        scenario.Attribute("Value")?.Value == "12")
                    .Descendants(policyNamespace + "AllowedSigner"),
                reference => reference.Attribute("SignerId") is not null);
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
            PolicyWorkflowService workflow = CreateWorkflow(templatesPath);
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

    private static PolicyWorkflowService CreateWorkflow(string templatesPath)
    {
        return new PolicyWorkflowService(
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
    }
}
