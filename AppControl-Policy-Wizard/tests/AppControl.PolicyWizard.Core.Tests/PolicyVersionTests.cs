using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Core.Tests;

public sealed class PolicyVersionTests
{
    [Theory]
    [InlineData("1.0.0.0", "1.0.0.1")]
    [InlineData("1.0.0.65534", "1.0.1.0")]
    [InlineData("1.0.65534.65534", "1.1.0.0")]
    [InlineData("65535.65535.65535.65535", "0.0.0.0")]
    public void IncrementMatchesProductionRollover(string current, string expected)
    {
        Assert.Equal(expected, PolicyVersion.Increment(current));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("1.0.0")]
    [InlineData("1.0.invalid.0")]
    [InlineData("1.0.0.65536")]
    [InlineData("1.0.0.-1")]
    public void IncrementRejectsInvalidVersions(string? version)
    {
        Assert.Throws<InvalidDataException>(() => PolicyVersion.Increment(version));
    }
}
