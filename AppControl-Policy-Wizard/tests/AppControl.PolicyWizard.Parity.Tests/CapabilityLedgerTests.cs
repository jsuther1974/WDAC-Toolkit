using System.Text.Json;

namespace AppControl.PolicyWizard.Parity.Tests;

public sealed class CapabilityLedgerTests
{
    private static readonly HashSet<string> AllowedStatuses =
    [
        "legacy-only",
        "characterized",
        "implemented",
        "validated",
        "legacy-retired",
        "deferred"
    ];

    private static readonly HashSet<string> AllowedDecisionStatuses =
    [
        "pending-review",
        "proposed",
        "accepted"
    ];

    [Fact]
    public void LedgerContainsUniqueCapabilitiesWithValidStatuses()
    {
        using JsonDocument ledger = JsonDocument.Parse(
            File.ReadAllText(
                Path.Combine(AppContext.BaseDirectory, "Migration", "capabilities.json")));
        JsonElement capabilities = ledger.RootElement.GetProperty("capabilities");
        var identifiers = new HashSet<string>(StringComparer.Ordinal);

        foreach (JsonElement capability in capabilities.EnumerateArray())
        {
            string identifier = capability.GetProperty("id").GetString()!;
            string status = capability.GetProperty("migrationStatus").GetString()!;
            string decisionStatus = capability.GetProperty("decisionStatus").GetString()!;

            Assert.True(identifiers.Add(identifier), $"Duplicate capability ID: {identifier}");
            Assert.Contains(status, AllowedStatuses);
            Assert.Contains(decisionStatus, AllowedDecisionStatuses);
            Assert.False(
                string.IsNullOrWhiteSpace(
                    capability.GetProperty("targetDirection").GetString()));

            if (status is "implemented" or "validated" or "legacy-retired")
            {
                Assert.NotEmpty(capability.GetProperty("successorEvidence").EnumerateArray());
            }

            if (status is "validated" or "legacy-retired")
            {
                Assert.Equal("accepted", decisionStatus);
            }
        }
    }

    [Fact]
    public void PolicyOptionEditingIsValidatedWithRemoteEvidence()
    {
        using JsonDocument ledger = JsonDocument.Parse(
            File.ReadAllText(
                Path.Combine(AppContext.BaseDirectory, "Migration", "capabilities.json")));

        JsonElement policyOptions = ledger.RootElement
            .GetProperty("capabilities")
            .EnumerateArray()
            .Single(capability =>
                capability.GetProperty("id").GetString() == "policy-option-editing");

        Assert.Equal(
            "validated",
            policyOptions.GetProperty("migrationStatus").GetString());
        Assert.Contains(
            policyOptions.GetProperty("successorEvidence").EnumerateArray(),
            evidence => evidence.GetString() == "GitHub Actions run 34917668908");
    }
}
