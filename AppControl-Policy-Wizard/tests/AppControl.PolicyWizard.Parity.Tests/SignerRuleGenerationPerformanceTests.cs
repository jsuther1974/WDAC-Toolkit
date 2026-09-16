using System.Xml.Linq;
using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.Infrastructure.Windows;

namespace AppControl.PolicyWizard.Parity.Tests;

public sealed class SignerRuleGenerationPerformanceTests
{
    [Fact]
    public async Task CacheReusesSuccessfulBatchResults()
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-signer-cache-{Guid.NewGuid():N}");
        Directory.CreateDirectory(testDirectory);
        string evidencePath = Path.Combine(testDirectory, "evidence.exe");
        await File.WriteAllTextAsync(evidencePath, "first");

        try
        {
            var inner = new RecordingSignerRuleGenerator();
            var cache = new CachedSignerRuleGenerator(
                inner,
                Path.Combine(testDirectory, "cache"),
                "test-version");
            var request = new SignerRuleGenerationRequest(
                evidencePath,
                SignerRuleLevel.Publisher,
                PolicyRuleAction.Allow);

            IReadOnlyList<SignerRuleGenerationOutcome> first =
                await cache.GenerateBatchAsync([request, request]);
            IReadOnlyList<SignerRuleGenerationOutcome> second =
                await cache.GenerateBatchAsync([request]);

            Assert.All(first, outcome => Assert.True(outcome.Succeeded));
            Assert.True(second[0].Succeeded);
            Assert.Equal(1, inner.BatchCalls);
            Assert.Equal(1, inner.RequestsProcessed);
        }
        finally
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task CacheInvalidatesWhenEvidenceChanges()
    {
        string testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"appcontrol-signer-cache-{Guid.NewGuid():N}");
        Directory.CreateDirectory(testDirectory);
        string evidencePath = Path.Combine(testDirectory, "evidence.exe");
        await File.WriteAllTextAsync(evidencePath, "first");

        try
        {
            var inner = new RecordingSignerRuleGenerator();
            var cache = new CachedSignerRuleGenerator(
                inner,
                Path.Combine(testDirectory, "cache"),
                "test-version");
            var request = new SignerRuleGenerationRequest(
                evidencePath,
                SignerRuleLevel.Publisher,
                PolicyRuleAction.Allow);

            await cache.GenerateAsync(request);
            await File.WriteAllTextAsync(evidencePath, "second");
            await cache.GenerateAsync(request);

            Assert.Equal(2, inner.BatchCalls);
            Assert.Equal(2, inner.RequestsProcessed);
        }
        finally
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task ConfigCiProcessesMultipleRequestsInOneBatch()
    {
        string evidencePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "notepad.exe");
        var generator = new PowerShellSignerRuleGenerator(
            Path.Combine(
                AppContext.BaseDirectory,
                "Scripts",
                "CreateSignerRule.ps1"));
        SignerRuleGenerationRequest[] requests =
        [
            new(
                evidencePath,
                SignerRuleLevel.FilePublisher,
                PolicyRuleAction.Allow,
                SignerFileNameLevel.OriginalFileName),
            new(
                evidencePath,
                SignerRuleLevel.Publisher,
                PolicyRuleAction.Allow),
            new(
                evidencePath,
                SignerRuleLevel.PcaCertificate,
                PolicyRuleAction.Allow)
        ];

        IReadOnlyList<SignerRuleGenerationOutcome> outcomes =
            await generator.GenerateBatchAsync(requests);

        Assert.Equal(requests, outcomes.Select(outcome => outcome.Request));
        Assert.All(outcomes, outcome =>
        {
            Assert.True(outcome.Succeeded, outcome.Error);
            Assert.True(outcome.Result!.IsSignerRule);
        });
    }

    private sealed class RecordingSignerRuleGenerator : ISignerRuleGenerator
    {
        public int BatchCalls { get; private set; }

        public int RequestsProcessed { get; private set; }

        public async Task<SignerRuleGenerationResult> GenerateAsync(
            SignerRuleGenerationRequest request,
            CancellationToken cancellationToken = default)
        {
            IReadOnlyList<SignerRuleGenerationOutcome> outcomes =
                await GenerateBatchAsync([request], cancellationToken);
            return outcomes[0].Result!;
        }

        public Task<IReadOnlyList<SignerRuleGenerationOutcome>>
            GenerateBatchAsync(
                IReadOnlyList<SignerRuleGenerationRequest> requests,
                CancellationToken cancellationToken = default)
        {
            BatchCalls++;
            RequestsProcessed += requests.Count;
            IReadOnlyList<SignerRuleGenerationOutcome> outcomes = requests
                .Select(request => new SignerRuleGenerationOutcome(
                    request,
                    new SignerRuleGenerationResult(
                        request.Level,
                        CreateFragment(),
                        SignerCount: 1,
                        HashRuleCount: 0,
                        Diagnostic: null,
                        request.SpecificFileNameLevel,
                        FileAttributeCount: request.Level
                            == SignerRuleLevel.FilePublisher
                                ? 1
                                : 0),
                    Error: null))
                .ToArray();
            return Task.FromResult(outcomes);
        }

        private static PolicyRuleFragment CreateFragment()
        {
            XNamespace ns = PolicyDocumentService.PolicyNamespace;
            return new PolicyRuleFragment(
                new XDocument(
                    new XElement(
                        ns + "SiPolicy",
                        new XElement(ns + "FileRules"),
                        new XElement(
                            ns + "Signers",
                            new XElement(
                                ns + "Signer",
                                new XAttribute("ID", "ID_SIGNER_TEST"),
                                new XAttribute("Name", "Test signer"),
                                new XElement(
                                    ns + "CertRoot",
                                    new XAttribute("Type", "TBS"),
                                    new XAttribute("Value", "00")))),
                        new XElement(ns + "SigningScenarios"))));
        }
    }
}
