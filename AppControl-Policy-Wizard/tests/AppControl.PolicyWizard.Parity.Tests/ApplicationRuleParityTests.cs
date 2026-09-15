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

    [Theory]
    [InlineData(SignerFileNameLevel.OriginalFileName, "FileName")]
    [InlineData(SignerFileNameLevel.InternalName, "InternalName")]
    [InlineData(SignerFileNameLevel.FileDescription, "FileDescription")]
    [InlineData(SignerFileNameLevel.ProductName, "ProductName")]
    [InlineData(SignerFileNameLevel.FilePath, "FilePath")]
    public async Task SpecificFilePublisherRuleCompilesWithConfigCi(
        SignerFileNameLevel fileNameLevel,
        string expectedAttribute)
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-filepublisher-parity-{Guid.NewGuid():N}");
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
            string evidencePath = GetNotepadPath();
            var generator = CreateSignerGenerator();

            SignerRuleGenerationResult generated =
                await generator.GenerateAsync(
                    new SignerRuleGenerationRequest(
                        evidencePath,
                        SignerRuleLevel.FilePublisher,
                        PolicyRuleAction.Allow,
                        fileNameLevel));
            PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
                evidencePath,
                PolicyRuleScenario.Applications,
                generated,
                configuration.RuleGraph);

            Assert.True(candidate.CanApply, candidate.UnavailableReason);
            Assert.Contains(
                candidate.Conditions.Keys,
                key => key == $"FileAttribute[0].{expectedAttribute}");
            configuration.ApplyRules([new PolicyRuleAddition(candidate)]);
            string outputPath = Path.Combine(
                testDirectory,
                $"{fileNameLevel}.xml");

            PolicyBuildResult result = await workflow.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.SignedAndReputable,
                    ExistingPolicyPath: null,
                    $"{fileNameLevel} FilePublisher parity",
                    outputPath,
                    configuration));

            XDocument output = XDocument.Load(result.XmlPath);
            XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
            Assert.Contains(
                output.Root!
                    .Element(policyNamespace + "FileRules")!
                    .Elements(policyNamespace + "FileAttrib"),
                attribute => attribute.Attribute(expectedAttribute) is not null);
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
    public async Task MissingPackageFamilyNameDoesNotBecomeUsableFallback()
    {
        PowerShellSignerRuleGenerator generator = CreateSignerGenerator();

        SignerRuleGenerationResult generated =
            await generator.GenerateAsync(
                new SignerRuleGenerationRequest(
                    GetNotepadPath(),
                    SignerRuleLevel.FilePublisher,
                    PolicyRuleAction.Allow,
                    SignerFileNameLevel.PackageFamilyName));
        PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
            GetNotepadPath(),
            PolicyRuleScenario.Applications,
            generated,
            new PolicyRuleGraphSnapshot([], []));

        Assert.False(candidate.CanApply);
        Assert.Null(candidate.Fragment);
        Assert.True(
            candidate.UnavailableReason?.Contains(
                "hash fallback",
                StringComparison.OrdinalIgnoreCase) == true
            || candidate.UnavailableReason?.Contains(
                "without the requested file attribute",
                StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public async Task PackageFamilyNameGenerationIsUsableOrExplicitlyUnavailable()
    {
        string evidencePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "SystemApps",
            "Microsoft.Windows.FilePicker_cw5n1h2txyewy",
            "FilePicker.exe");
        if (!File.Exists(evidencePath))
        {
            return;
        }

        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-pfn-parity-{Guid.NewGuid():N}");
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
            SignerRuleGenerationResult generated =
                await CreateSignerGenerator().GenerateAsync(
                    new SignerRuleGenerationRequest(
                        evidencePath,
                        SignerRuleLevel.FilePublisher,
                        PolicyRuleAction.Allow,
                        SignerFileNameLevel.PackageFamilyName));
            PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
                evidencePath,
                PolicyRuleScenario.Applications,
                generated,
                configuration.RuleGraph);

            if (!candidate.CanApply)
            {
                Assert.Null(candidate.Fragment);
                Assert.True(
                    generated.UsedHashFallback
                    || generated.FileAttributeCount == 0);
                return;
            }

            Assert.Contains(
                candidate.Conditions.Keys,
                key => key == "FileAttribute[0].PackageFamilyName");
            Assert.Contains(
                candidate.Conditions.Keys,
                key => key == "FileAttribute[0].PackageVersion");
            configuration.ApplyRules([new PolicyRuleAddition(candidate)]);
            string outputPath = Path.Combine(
                testDirectory,
                "PackageFamilyName.xml");
            PolicyBuildResult result = await workflow.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.SignedAndReputable,
                    ExistingPolicyPath: null,
                    "Package family name parity",
                    outputPath,
                    configuration));

            XDocument output = XDocument.Load(result.XmlPath);
            XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
            Assert.Contains(
                output.Root!
                    .Element(policyNamespace + "FileRules")!
                    .Elements(policyNamespace + "FileAttrib"),
                attribute =>
                    attribute.Attribute("PackageFamilyName") is not null
                    && attribute.Attribute("PackageVersion") is not null);
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
    public async Task OpusAndMultipleEkuSignerCompilesWithConfigCi()
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-opus-parity-{Guid.NewGuid():N}");
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
            SignerRuleGenerationResult generated =
                await CreateSignerGenerator().GenerateAsync(
                    new SignerRuleGenerationRequest(
                        GetNotepadPath(),
                        SignerRuleLevel.Publisher,
                        PolicyRuleAction.Allow));
            XDocument fragment = generated.Fragment.CloneDocument();
            XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
            XElement root = fragment.Root!;
            XElement ekus = root.Element(policyNamespace + "EKUs")!;
            ekus.Add(
                new XElement(
                    policyNamespace + "EKU",
                    new XAttribute("ID", "ID_EKU_OPUS_A"),
                    new XAttribute("Value", "010A2B0601040182370A0306")),
                new XElement(
                    policyNamespace + "EKU",
                    new XAttribute("ID", "ID_EKU_OPUS_B"),
                    new XAttribute("Value", "010A2B0601040182370A0305")));
            XElement signer = Assert.Single(
                root.Element(policyNamespace + "Signers")!
                    .Elements(policyNamespace + "Signer"));
            XElement? publisher =
                signer.Element(policyNamespace + "CertPublisher");
            publisher!.AddBeforeSelf(
                new XElement(
                    policyNamespace + "CertEKU",
                    new XAttribute("ID", "ID_EKU_OPUS_A")),
                new XElement(
                    policyNamespace + "CertEKU",
                    new XAttribute("ID", "ID_EKU_OPUS_B")));
            publisher.AddAfterSelf(
                new XElement(
                    policyNamespace + "CertOemID",
                    new XAttribute("Value", "Contoso OPUS")));
            generated = generated with
            {
                Fragment = new PolicyRuleFragment(fragment)
            };
            PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
                GetNotepadPath(),
                PolicyRuleScenario.Applications,
                generated,
                configuration.RuleGraph);

            configuration.ApplyRules([new PolicyRuleAddition(candidate)]);
            string outputPath = Path.Combine(testDirectory, "OpusEku.xml");
            PolicyBuildResult result = await workflow.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.SignedAndReputable,
                    ExistingPolicyPath: null,
                    "OPUS and EKU signer parity",
                    outputPath,
                    configuration));

            XDocument output = XDocument.Load(result.XmlPath);
            Assert.Contains(
                output.Root!
                    .Element(policyNamespace + "Signers")!
                    .Elements(policyNamespace + "Signer"),
                outputSigner =>
                    outputSigner.Element(policyNamespace + "CertOemID")?
                        .Attribute("Value")?.Value == "Contoso OPUS"
                    && outputSigner.Elements(policyNamespace + "CertEKU").Count()
                        == 2);
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

    private static PowerShellSignerRuleGenerator CreateSignerGenerator()
    {
        return new PowerShellSignerRuleGenerator(
            Path.Combine(
                AppContext.BaseDirectory,
                "Scripts",
                "CreateSignerRule.ps1"));
    }

    private static string GetNotepadPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "notepad.exe");
    }
}
