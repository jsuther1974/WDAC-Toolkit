using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.Infrastructure.Windows;
using System.Security.Cryptography;

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

    public static ISignerRuleGenerator CreateSignerRuleGenerator()
    {
        string scriptPath = Path.Combine(
            AppContext.BaseDirectory,
            "Scripts",
            "CreateSignerRule.ps1");
        string versionToken = Convert.ToHexString(
            SHA256.HashData(File.ReadAllBytes(scriptPath)));
        var generator = new PowerShellSignerRuleGenerator(scriptPath);
        return new CachedSignerRuleGenerator(
            generator,
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "AppControl.PolicyWizard",
                "SignerCache"),
            versionToken);
    }
}
