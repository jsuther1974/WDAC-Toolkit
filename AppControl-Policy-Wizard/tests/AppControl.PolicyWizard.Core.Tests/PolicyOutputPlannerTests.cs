using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Core.Tests;

public sealed class PolicyOutputPlannerTests
{
    [Fact]
    public void ExistingPolicyDefaultNameReplacesVersionSuffix()
    {
        var policy = new PolicySourceInfo(
            @"C:\Policies\Contoso_v1.2.3.4.xml",
            "{11111111-1111-1111-1111-111111111111}",
            "{11111111-1111-1111-1111-111111111111}",
            "1.2.3.4",
            "1.2.3.5",
            "Contoso");

        string name = PolicyOutputPlanner.CreateDefaultBaseName(
            PolicySourceKind.ExistingPolicy,
            policy,
            new DateOnly(2026, 9, 14));

        Assert.Equal("Contoso_v1.2.3.5", name);
    }

    [Fact]
    public void TemplateDefaultNameUsesProvidedDate()
    {
        string name = PolicyOutputPlanner.CreateDefaultBaseName(
            PolicySourceKind.SignedAndReputable,
            existingPolicy: null,
            new DateOnly(2026, 9, 14));

        Assert.Equal("SignedAndReputable_2026-09-14", name);
    }

    [Fact]
    public void AvailablePathsAvoidExistingFilesAndDirectories()
    {
        using var testDirectory = new TestDirectory();
        string flatPath = Path.Combine(testDirectory.Path, "Policy.xml");
        File.WriteAllText(flatPath, "existing");
        Directory.CreateDirectory(Path.Combine(testDirectory.Path, "Policy"));

        string availableFlatPath = PolicyOutputPlanner.GetAvailableOutputPath(
            testDirectory.Path,
            "Policy",
            useDedicatedDirectory: false);
        string availableDedicatedPath = PolicyOutputPlanner.GetAvailableOutputPath(
            testDirectory.Path,
            "Policy",
            useDedicatedDirectory: true);

        Assert.Equal(Path.Combine(testDirectory.Path, "Policy_2.xml"), availableFlatPath);
        Assert.Equal(
            Path.Combine(testDirectory.Path, "Policy_2", "Policy_2.xml"),
            availableDedicatedPath);
    }
}
