namespace AppControl.PolicyWizard.Core.Tests;

internal sealed class TestDirectory : IDisposable
{
    public TestDirectory()
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"wdac-wizard-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string WritePolicy(
        string fileName,
        string version,
        string? policyId,
        string? basePolicyId,
        string policyName)
    {
        string policyPath = System.IO.Path.Combine(Path, fileName);
        string policyIdElement = policyId is null
            ? string.Empty
            : $"<PolicyID>{policyId}</PolicyID>";
        string basePolicyIdElement = basePolicyId is null
            ? string.Empty
            : $"<BasePolicyID>{basePolicyId}</BasePolicyID>";
        string xml =
            $"""
             <?xml version="1.0" encoding="utf-8"?>
             <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
               <VersionEx>{version}</VersionEx>
               {policyIdElement}
               {basePolicyIdElement}
               <Rules>
                 <Rule>
                   <Option>Enabled:Audit Mode</Option>
                 </Rule>
               </Rules>
               <Settings>
                 <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
                   <Value>
                     <String>{policyName}</String>
                   </Value>
                 </Setting>
               </Settings>
             </SiPolicy>
             """;
        File.WriteAllText(policyPath, xml);
        return policyPath;
    }

    public void Dispose()
    {
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
