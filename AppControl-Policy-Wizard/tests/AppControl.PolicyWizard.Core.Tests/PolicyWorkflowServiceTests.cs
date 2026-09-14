using System.Xml.Linq;
using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Core.Tests;

public sealed class PolicyWorkflowServiceTests
{
    [Fact]
    public async Task ExistingPolicyPreservesIdentityAndRulesAndIncrementsVersion()
    {
        using var testDirectory = new TestDirectory();
        string sourcePath = testDirectory.WritePolicy(
            "Existing.xml",
            version: "1.0.0.0",
            policyId: "{11111111-1111-1111-1111-111111111111}",
            basePolicyId: "{22222222-2222-2222-2222-222222222222}",
            policyName: "Existing policy");
        string outputPath = Path.Combine(testDirectory.Path, "Output", "Existing_v1.0.0.1.xml");
        var compiler = new FakePolicyCompiler();
        var service = CreateService(compiler, sourcePath);
        var progress = new ProgressCollector();

        PolicyBuildResult result = await service.BuildAsync(
            new PolicyBuildRequest(
                PolicySourceKind.ExistingPolicy,
                sourcePath,
                "Existing policy",
                outputPath),
            progress);

        Assert.False(compiler.LastRequest!.ResetPolicyIdentity);
        Assert.Equal("1.0.0.1", compiler.LastRequest.Version);
        Assert.Equal("{11111111-1111-1111-1111-111111111111}", result.PolicyID);
        Assert.Equal("{22222222-2222-2222-2222-222222222222}", result.BasePolicyID);
        Assert.Equal("1.0.0.1", result.Version);
        Assert.True(File.Exists(result.XmlPath));
        Assert.True(File.Exists(result.BinaryPath));

        XDocument source = XDocument.Load(sourcePath);
        XDocument output = XDocument.Load(result.XmlPath);
        XNamespace ns = PolicyDocumentService.PolicyNamespace;
        Assert.True(XNode.DeepEquals(
            source.Root!.Element(ns + "Rules"),
            output.Root!.Element(ns + "Rules")));
        Assert.Equal(
            source.Root.Element(ns + "PolicyID")?.Value,
            output.Root.Element(ns + "PolicyID")?.Value);
        Assert.Equal(
            source.Root.Element(ns + "BasePolicyID")?.Value,
            output.Root.Element(ns + "BasePolicyID")?.Value);
        Assert.Equal("1.0.0.1", output.Root.Element(ns + "VersionEx")?.Value);
        Assert.Equal(
            new[]
            {
                PolicyBuildStage.Validating,
                PolicyBuildStage.Preparing,
                PolicyBuildStage.Compiling,
                PolicyBuildStage.Finalizing
            },
            progress.Stages);
    }

    [Fact]
    public async Task TemplatePolicyReceivesNewIdentityAndInitialVersion()
    {
        using var testDirectory = new TestDirectory();
        string templatePath = testDirectory.WritePolicy(
            "Template.xml",
            version: "10.3.0.0",
            policyId: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
            basePolicyId: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
            policyName: "Template");
        string outputPath = Path.Combine(testDirectory.Path, "Output", "NewPolicy.xml");
        var compiler = new FakePolicyCompiler();
        var service = CreateService(compiler, templatePath);

        PolicyBuildResult result = await service.BuildAsync(
            new PolicyBuildRequest(
                PolicySourceKind.SignedAndReputable,
                ExistingPolicyPath: null,
                "New policy",
                outputPath));

        Assert.True(compiler.LastRequest!.ResetPolicyIdentity);
        Assert.Equal("1.0.0.0", compiler.LastRequest.Version);
        Assert.Equal(FakePolicyCompiler.NewPolicyId, result.PolicyID);
        Assert.Equal(FakePolicyCompiler.NewPolicyId, result.BasePolicyID);
        Assert.Equal("1.0.0.0", result.Version);
    }

    [Fact]
    public async Task ExistingPolicyRejectsCompilerIdentityChanges()
    {
        using var testDirectory = new TestDirectory();
        string sourcePath = testDirectory.WritePolicy(
            "Existing.xml",
            version: "1.0.0.0",
            policyId: "{11111111-1111-1111-1111-111111111111}",
            basePolicyId: "{22222222-2222-2222-2222-222222222222}",
            policyName: "Existing policy");
        string outputPath = Path.Combine(testDirectory.Path, "Output", "Existing.xml");
        var compiler = new FakePolicyCompiler { ChangeExistingIdentity = true };
        var service = CreateService(compiler, sourcePath);

        PolicyBuildException exception = await Assert.ThrowsAsync<PolicyBuildException>(
            () => service.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.ExistingPolicy,
                    sourcePath,
                    "Existing policy",
                    outputPath)));

        Assert.Contains("changed the identity", exception.Message);
        Assert.False(File.Exists(outputPath));
        Assert.Empty(
            Directory.Exists(Path.GetDirectoryName(outputPath))
                ? Directory.EnumerateDirectories(
                    Path.GetDirectoryName(outputPath)!,
                    ".wdac-build-*")
                : []);
    }

    [Fact]
    public async Task WorkflowRejectsBinaryOutsideWorkingDirectory()
    {
        using var testDirectory = new TestDirectory();
        string templatePath = testDirectory.WritePolicy(
            "Template.xml",
            version: "10.3.0.0",
            policyId: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
            basePolicyId: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
            policyName: "Template");
        string outputPath = Path.Combine(testDirectory.Path, "Output", "NewPolicy.xml");
        var compiler = new FakePolicyCompiler
        {
            ExternalBinaryPath = Path.Combine(testDirectory.Path, "External.cip")
        };
        var service = CreateService(compiler, templatePath);

        PolicyBuildException exception = await Assert.ThrowsAsync<PolicyBuildException>(
            () => service.BuildAsync(
                new PolicyBuildRequest(
                    PolicySourceKind.SignedAndReputable,
                    ExistingPolicyPath: null,
                    "New policy",
                    outputPath)));

        Assert.Contains("outside the isolated working directory", exception.Message);
        Assert.False(File.Exists(outputPath));
    }

    private static PolicyWorkflowService CreateService(
        IPolicyCompiler compiler,
        string templatePath)
    {
        return new PolicyWorkflowService(
            compiler,
            new Dictionary<PolicySourceKind, string>
            {
                [PolicySourceKind.SignedAndReputable] = templatePath,
                [PolicySourceKind.WindowsOnly] = templatePath
            });
    }

    private sealed class FakePolicyCompiler : IPolicyCompiler
    {
        public const string NewPolicyId = "{99999999-9999-9999-9999-999999999999}";

        public bool ChangeExistingIdentity { get; init; }

        public string? ExternalBinaryPath { get; init; }

        public PolicyCompileRequest? LastRequest { get; private set; }

        public Task<PolicyCompileResult> CompileAsync(
            PolicyCompileRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastRequest = request;

            XDocument document = XDocument.Load(request.XmlPath);
            XNamespace ns = PolicyDocumentService.PolicyNamespace;
            XElement root = document.Root!;
            XElement version = root.Element(ns + "VersionEx")
                ?? throw new InvalidDataException("Missing VersionEx.");
            version.Value = request.Version;

            string? policyId = root.Element(ns + "PolicyID")?.Value;
            string? basePolicyId = root.Element(ns + "BasePolicyID")?.Value;
            if (request.ResetPolicyIdentity || ChangeExistingIdentity)
            {
                policyId = NewPolicyId;
                basePolicyId = NewPolicyId;
                root.SetElementValue(ns + "PolicyID", policyId);
                root.SetElementValue(ns + "BasePolicyID", basePolicyId);
            }

            document.Save(request.XmlPath);
            string binaryFileName = string.IsNullOrWhiteSpace(policyId)
                ? "SiPolicy.p7b"
                : $"{policyId}.cip";
            string binaryPath = ExternalBinaryPath
                ?? Path.Combine(
                    Path.GetDirectoryName(request.XmlPath)!,
                    binaryFileName);
            File.WriteAllBytes(binaryPath, [0x01, 0x02, 0x03]);

            return Task.FromResult(
                new PolicyCompileResult(
                    policyId,
                    basePolicyId,
                    request.Version,
                    binaryPath));
        }
    }

    private sealed class ProgressCollector : IProgress<PolicyBuildProgress>
    {
        public List<PolicyBuildStage> Stages { get; } = [];

        public void Report(PolicyBuildProgress value)
        {
            Stages.Add(value.Stage);
        }
    }
}
