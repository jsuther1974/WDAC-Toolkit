namespace AppControl.PolicyWizard.Core;

public enum PolicySourceKind
{
    SignedAndReputable,
    WindowsOnly,
    ExistingPolicy
}

public sealed record PolicySourceInfo(
    string Path,
    string? PolicyID,
    string? BasePolicyID,
    string Version,
    string NextVersion,
    string? PolicyName);

public sealed record PolicyBuildRequest(
    PolicySourceKind SourceKind,
    string? ExistingPolicyPath,
    string PolicyName,
    string OutputPath);

public sealed record PolicyBuildResult(
    string XmlPath,
    string BinaryPath,
    string? PolicyID,
    string? BasePolicyID,
    string Version);

public sealed record PolicyCompileRequest(
    string XmlPath,
    string PolicyName,
    bool ResetPolicyIdentity,
    string Version);

public sealed record PolicyCompileResult(
    string? PolicyID,
    string? BasePolicyID,
    string Version,
    string BinaryPath);

public enum PolicyBuildStage
{
    Validating,
    Preparing,
    Compiling,
    Finalizing
}

public sealed record PolicyBuildProgress(PolicyBuildStage Stage, string Message);

public sealed class PolicyBuildException : Exception
{
    public PolicyBuildException(string message)
        : base(message)
    {
    }

    public PolicyBuildException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
