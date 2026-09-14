using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Core.Tests;

public sealed class PolicyDocumentServiceTests
{
    [Fact]
    public void InspectExistingPolicyReadsIdentityNameAndNextVersion()
    {
        using var testDirectory = new TestDirectory();
        string policyPath = testDirectory.WritePolicy(
            "Existing.xml",
            version: "2.3.4.5",
            policyId: "{11111111-1111-1111-1111-111111111111}",
            basePolicyId: "{22222222-2222-2222-2222-222222222222}",
            policyName: "Existing policy");

        var service = new PolicyDocumentService();
        PolicySourceInfo policy = service.InspectExistingPolicy(policyPath);

        Assert.Equal(Path.GetFullPath(policyPath), policy.Path);
        Assert.Equal("{11111111-1111-1111-1111-111111111111}", policy.PolicyID);
        Assert.Equal("{22222222-2222-2222-2222-222222222222}", policy.BasePolicyID);
        Assert.Equal("2.3.4.5", policy.Version);
        Assert.Equal("2.3.4.6", policy.NextVersion);
        Assert.Equal("Existing policy", policy.PolicyName);
    }

    [Fact]
    public void InspectExistingPolicyRejectsNonPolicyXml()
    {
        using var testDirectory = new TestDirectory();
        string path = Path.Combine(testDirectory.Path, "NotPolicy.xml");
        File.WriteAllText(path, "<root />");

        var service = new PolicyDocumentService();

        Assert.Throws<InvalidDataException>(() => service.InspectExistingPolicy(path));
    }
}
