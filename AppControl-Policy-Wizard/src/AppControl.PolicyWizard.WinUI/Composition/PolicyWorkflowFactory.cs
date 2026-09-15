using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.Infrastructure.Windows;

namespace AppControl.PolicyWizard.WinUI.Composition;

internal static class PolicyWorkflowFactory
{
    public static PolicyWorkflowService Create()
    {
        string applicationDirectory = AppContext.BaseDirectory;
        var templatePaths = new Dictionary<PolicySourceKind, string>
        {
            [PolicySourceKind.SignedAndReputable] =
                Path.Combine(applicationDirectory, "Templates", "SignedReputable.xml"),
            [PolicySourceKind.WindowsOnly] =
                Path.Combine(applicationDirectory, "Templates", "DefaultWindows_Audit.xml")
        };

        var compiler = new PowerShellConfigCiCompiler(
            Path.Combine(applicationDirectory, "Scripts", "CreateBasePolicy.ps1"));
        PolicyTemplateManifest templateManifest = PolicyTemplateManifest.Load(
            Path.Combine(applicationDirectory, "Templates", "template-manifest.json"));

        return new PolicyWorkflowService(
            compiler,
            templatePaths,
            templateManifest: templateManifest);
    }
}
