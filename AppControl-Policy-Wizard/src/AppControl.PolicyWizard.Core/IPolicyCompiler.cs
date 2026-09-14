namespace AppControl.PolicyWizard.Core;

public interface IPolicyCompiler
{
    Task<PolicyCompileResult> CompileAsync(
        PolicyCompileRequest request,
        CancellationToken cancellationToken = default);
}
