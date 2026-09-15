using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Core.Tests;

public sealed class FolderEvidenceInventoryScannerTests
{
    [Fact]
    public void ScanBuildsRecursiveSupportedFileInventory()
    {
        using var directory = new InventoryTestDirectory();
        directory.Write("Contoso.exe");
        directory.Write(Path.Combine("Drivers", "Contoso.sys"));
        directory.Write("Readme.txt");
        var scanner = new FolderEvidenceInventoryScanner();

        FolderInventoryResult result = scanner.Scan(directory.Path);

        Assert.Equal(2, result.Items.Count);
        Assert.Equal(1, result.UnsupportedFileCount);
        Assert.Equal(
            PolicyRuleScenario.Applications,
            result.Items.Single(item =>
                item.RelativePath == "Contoso.exe").Scenario);
        Assert.Equal(
            PolicyRuleScenario.Drivers,
            result.Items.Single(item =>
                item.RelativePath == Path.Combine("Drivers", "Contoso.sys")).Scenario);
        Assert.False(result.WasTruncated);
    }

    [Fact]
    public void ScanReportsAnExplicitInventoryLimit()
    {
        using var directory = new InventoryTestDirectory();
        directory.Write("One.exe");
        directory.Write("Two.dll");
        var scanner = new FolderEvidenceInventoryScanner();

        FolderInventoryResult result = scanner.Scan(
            directory.Path,
            maximumFiles: 1);

        Assert.Single(result.Items);
        Assert.True(result.WasTruncated);
    }

    [Fact]
    public void ScanRejectsMissingFolder()
    {
        var scanner = new FolderEvidenceInventoryScanner();

        Assert.Throws<DirectoryNotFoundException>(
            () => scanner.Scan(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))));
    }

    [Fact]
    public void CandidateClustererGroupsEquivalentIdentityAndKeepsLowestVersion()
    {
        var candidates = new List<PolicyRuleCandidate>();
        PolicyRuleCandidate versionTwo = CreateFilePublisherCandidate(
            @"C:\Contoso\v2\Contoso.exe",
            "2.0.0.0");
        PolicyRuleCandidate versionOne = CreateFilePublisherCandidate(
            @"C:\Contoso\v1\Contoso.exe",
            "1.0.0.0");

        FolderRuleCandidateClusterer.AddOrMerge(candidates, versionTwo);
        FolderRuleCandidateClusterer.AddOrMerge(candidates, versionOne);

        PolicyRuleCandidate clustered = Assert.Single(candidates);
        Assert.Equal(
            "1.0.0.0",
            clustered.Conditions["FileAttribute[0].MinimumFileVersion"]);
        Assert.Equal(2, clustered.EvidencePaths.Count);
        Assert.Contains(versionOne.EvidencePath, clustered.EvidencePaths);
        Assert.Contains(versionTwo.EvidencePath, clustered.EvidencePaths);
    }

    [Fact]
    public void CandidateClustererKeepsDifferentIdentitiesSeparate()
    {
        var candidates = new List<PolicyRuleCandidate>();
        PolicyRuleCandidate first = CreateFilePublisherCandidate(
            @"C:\Contoso\One.exe",
            "1.0.0.0");
        PolicyRuleCandidate second = CreateFilePublisherCandidate(
            @"C:\Contoso\Two.exe",
            "1.0.0.0") with
        {
            Conditions = new Dictionary<string, string>(
                first.Conditions,
                StringComparer.Ordinal)
            {
                ["FileAttribute[0].FileName"] = "Two.exe"
            }
        };

        FolderRuleCandidateClusterer.AddOrMerge(candidates, first);
        FolderRuleCandidateClusterer.AddOrMerge(candidates, second);

        Assert.Equal(2, candidates.Count);
    }

    private static PolicyRuleCandidate CreateFilePublisherCandidate(
        string path,
        string minimumVersion)
    {
        return new PolicyRuleCandidate(
            Guid.NewGuid().ToString("N"),
            PolicyRuleAction.Allow,
            PolicyRuleIdentity.FilePublisher,
            PolicyRuleScenario.Applications,
            "Contoso publisher and original filename",
            $"Match Contoso.exe from version {minimumVersion}",
            path,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["CertRoot"] = "AABBCC",
                ["CertPublisher"] = "Contoso Ltd",
                ["FileAttribute[0].FileName"] = "Contoso.exe",
                ["FileAttribute[0].MinimumFileVersion"] = minimumVersion
            },
            RuleTrustBreadth.Narrow,
            RuleUpdateResilience.High,
            RuleEvidenceQuality.Verified,
            [],
            CanApply: true);
    }

    private sealed class InventoryTestDirectory : IDisposable
    {
        public InventoryTestDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"appcontrol-folder-inventory-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Write(string relativePath)
        {
            string path = System.IO.Path.Combine(Path, relativePath);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            File.WriteAllText(path, relativePath);
        }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
