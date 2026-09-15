using System.Xml.Linq;
using AppControl.PolicyWizard.Core;

namespace AppControl.PolicyWizard.Core.Tests;

public sealed class PolicyRuleGraphEditorTests
{
    [Fact]
    public void SnapshotReconstructsFileRulesAndPreservesUnknownObjects()
    {
        XDocument document = XDocument.Parse(
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <FileRules>
                <Allow ID="ID_ALLOW_PATH" FriendlyName="Contoso path" FilePath="C:\Program Files\Contoso\App.exe" />
                <Deny ID="ID_DENY_HASH" FriendlyName="Blocked binary" Hash="ABCDEF" />
                <FileAttrib ID="ID_FILEATTRIB" FileName="Contoso.exe" MinimumFileVersion="1.0.0.0" />
              </FileRules>
              <Signers />
              <SigningScenarios>
                <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI">
                  <ProductSigners>
                    <FileRulesRef>
                      <FileRuleRef RuleID="ID_ALLOW_PATH" />
                    </FileRulesRef>
                  </ProductSigners>
                </SigningScenario>
                <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_KMCI">
                  <ProductSigners>
                    <FileRulesRef>
                      <FileRuleRef RuleID="ID_DENY_HASH" />
                    </FileRulesRef>
                  </ProductSigners>
                </SigningScenario>
              </SigningScenarios>
            </SiPolicy>
            """);

        PolicyRuleGraphSnapshot snapshot =
            PolicyRuleGraphEditor.FromDocument(document).Snapshot;

        Assert.Contains(
            snapshot.Rules,
            rule => rule.Id == "ID_ALLOW_PATH"
                && rule.Action == PolicyRuleAction.Allow
                && rule.Identity == PolicyRuleIdentity.FilePath
                && rule.Scenario == PolicyRuleScenario.Applications);
        Assert.Contains(
            snapshot.Rules,
            rule => rule.Id == "ID_DENY_HASH"
                && rule.Action == PolicyRuleAction.Deny
                && rule.Identity == PolicyRuleIdentity.Hash
                && rule.Scenario == PolicyRuleScenario.Drivers);
        Assert.Contains("ID_FILEATTRIB", snapshot.UnknownObjectIds);
    }

    [Fact]
    public void ApplyAddsRuleAndScenarioReferenceWithoutChangingExistingContent()
    {
        XDocument document = XDocument.Parse(
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <Rules><Rule><Option>Enabled:Audit Mode</Option></Rule></Rules>
              <FileRules>
                <Allow ID="ID_EXISTING" FriendlyName="Preserve me" FilePath="C:\Existing.exe" />
              </FileRules>
              <Signers />
              <SigningScenarios>
                <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI">
                  <ProductSigners>
                    <FileRulesRef><FileRuleRef RuleID="ID_EXISTING" /></FileRulesRef>
                  </ProductSigners>
                </SigningScenario>
              </SigningScenarios>
            </SiPolicy>
            """);
        var candidate = new PolicyRuleCandidate(
            "candidate",
            PolicyRuleAction.Allow,
            PolicyRuleIdentity.Hash,
            PolicyRuleScenario.Applications,
            "Exact Contoso binary",
            "Match SHA-256 ABCDEF",
            "Contoso.exe",
            new Dictionary<string, string> { ["Hash"] = "ABCDEF" },
            RuleTrustBreadth.ExactArtifact,
            RuleUpdateResilience.Low,
            RuleEvidenceQuality.Verified,
            [],
            CanApply: true);
        PolicyRuleGraphEditor editor = PolicyRuleGraphEditor.FromDocument(document);

        PolicyRuleChangeResult result = editor.Apply([new PolicyRuleAddition(candidate)]);

        XDocument output = editor.ToDocument();
        XNamespace ns = PolicyDocumentService.PolicyNamespace;
        XElement added = Assert.Single(
            output.Root!
                .Element(ns + "FileRules")!
                .Elements(ns + "Allow"),
            rule => rule.Attribute("Hash")?.Value == "ABCDEF");
        Assert.NotNull(
            output.Root
                .Element(ns + "SigningScenarios")!
                .Elements(ns + "SigningScenario")
                .Single(scenario => scenario.Attribute("Value")?.Value == "12")
                .Descendants(ns + "FileRuleRef")
                .SingleOrDefault(reference =>
                    reference.Attribute("RuleID")?.Value
                    == added.Attribute("ID")?.Value));
        Assert.Contains("ID_EXISTING", output.ToString());
        Assert.Single(result.Changes);
    }

    [Fact]
    public void ApplyingEquivalentRuleIsNoOp()
    {
        XDocument document = XDocument.Parse(
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <FileRules>
                <Allow ID="ID_EXISTING" FriendlyName="Existing" FilePath="C:\Contoso.exe" />
              </FileRules>
              <SigningScenarios>
                <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI">
                  <ProductSigners>
                    <FileRulesRef><FileRuleRef RuleID="ID_EXISTING" /></FileRulesRef>
                  </ProductSigners>
                </SigningScenario>
              </SigningScenarios>
            </SiPolicy>
            """);
        var candidate = new PolicyRuleCandidate(
            "candidate",
            PolicyRuleAction.Allow,
            PolicyRuleIdentity.FilePath,
            PolicyRuleScenario.Applications,
            "Contoso path",
            "Match code at C:\\Contoso.exe",
            "Contoso.exe",
            new Dictionary<string, string> { ["FilePath"] = "C:\\Contoso.exe" },
            RuleTrustBreadth.Moderate,
            RuleUpdateResilience.Medium,
            RuleEvidenceQuality.Complete,
            [],
            CanApply: true);
        PolicyRuleGraphEditor editor = PolicyRuleGraphEditor.FromDocument(document);

        PolicyRuleChangeResult result = editor.Apply([new PolicyRuleAddition(candidate)]);

        Assert.Empty(result.Changes);
        Assert.Single(editor.Snapshot.Rules);
    }

    [Fact]
    public void SnapshotCombinesSignerAttributesScenariosAndNestedExceptions()
    {
        XDocument document = XDocument.Parse(
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <FileRules>
                <FileAttrib ID="ID_ATTRIBUTE" FileName="Contoso.exe" MinimumFileVersion="2.0.0.0" />
                <Deny ID="ID_EXCEPTION" FileName="ContosoUpdater.exe" />
              </FileRules>
              <Signers>
                <Signer ID="ID_SIGNER" Name="Contoso Publisher">
                  <CertRoot Type="TBS" Value="AABBCC" />
                  <CertPublisher Value="Contoso Ltd" />
                  <FileAttribRef RuleID="ID_ATTRIBUTE" />
                </Signer>
              </Signers>
              <SigningScenarios>
                <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI">
                  <ProductSigners>
                    <AllowedSigners>
                      <AllowedSigner SignerId="ID_SIGNER">
                        <ExceptDenyRule DenyRuleID="ID_EXCEPTION" />
                      </AllowedSigner>
                    </AllowedSigners>
                  </ProductSigners>
                </SigningScenario>
                <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_KMCI">
                  <ProductSigners>
                    <AllowedSigners>
                      <AllowedSigner SignerId="ID_SIGNER" />
                    </AllowedSigners>
                  </ProductSigners>
                </SigningScenario>
              </SigningScenarios>
            </SiPolicy>
            """);

        PolicyRuleGraphSnapshot snapshot =
            PolicyRuleGraphEditor.FromDocument(document).Snapshot;

        PolicyLogicalRule signer = Assert.Single(snapshot.Rules);
        Assert.Equal("ID_SIGNER", signer.Id);
        Assert.Equal(PolicyRuleIdentity.FilePublisher, signer.Identity);
        Assert.Equal(PolicyRuleScenario.ApplicationsAndDrivers, signer.Scenario);
        Assert.Contains("ID_ATTRIBUTE", signer.ReferencedObjectIds);
        Assert.Contains("ID_EXCEPTION", signer.ExceptionRuleIds);
        Assert.Equal(
            "Contoso.exe",
            signer.Conditions["FileAttribute[0].FileName"]);
        Assert.Empty(snapshot.UnknownObjectIds);
    }

    [Fact]
    public void GeneratedFilePublisherFragmentIsRemappedAndLinkedToTargetScenario()
    {
        XDocument document = XDocument.Parse(
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <EKUs />
              <FileRules />
              <Signers />
              <SigningScenarios>
                <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI">
                  <ProductSigners />
                </SigningScenario>
              </SigningScenarios>
              <CiSigners />
            </SiPolicy>
            """);
        XDocument fragment = XDocument.Parse(
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <EKUs>
                <EKU ID="ID_EKU_A" Value="010A" />
                <EKU ID="ID_EKU_B" Value="010B" />
              </EKUs>
              <FileRules>
                <FileAttrib ID="ID_FILEATTRIB_A" FileName="Contoso.exe" MinimumFileVersion="2.0.0.0" />
              </FileRules>
              <Signers>
                <Signer ID="ID_SIGNER_A" Name="Contoso">
                  <CertRoot Type="TBS" Value="AABBCC" />
                  <CertEKU ID="ID_EKU_A" />
                  <CertEKU ID="ID_EKU_B" />
                  <CertPublisher Value="Contoso Ltd" />
                  <CertOemID Value="Contoso OPUS" />
                  <FileAttribRef RuleID="ID_FILEATTRIB_A" />
                </Signer>
              </Signers>
              <SigningScenarios>
                <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_SOURCE">
                  <ProductSigners>
                    <AllowedSigners>
                      <AllowedSigner SignerId="ID_SIGNER_A" />
                    </AllowedSigners>
                  </ProductSigners>
                </SigningScenario>
              </SigningScenarios>
              <CiSigners><CiSigner SignerId="ID_SIGNER_A" /></CiSigners>
            </SiPolicy>
            """);
        PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
            @"C:\Contoso.exe",
            PolicyRuleScenario.Applications,
            new SignerRuleGenerationResult(
                SignerRuleLevel.FilePublisher,
                new PolicyRuleFragment(fragment),
                SignerCount: 1,
                HashRuleCount: 0,
                Diagnostic: null,
                SignerFileNameLevel.OriginalFileName,
                FileAttributeCount: 1),
            new PolicyRuleGraphSnapshot([], []));
        Assert.Contains("OPUS", candidate.Title);
        Assert.Contains("2 EKU constraints", candidate.Effect);
        PolicyRuleGraphEditor editor = PolicyRuleGraphEditor.FromDocument(document);

        PolicyRuleChangeResult result = editor.Apply([new PolicyRuleAddition(candidate)]);

        XDocument output = editor.ToDocument();
        XNamespace ns = PolicyDocumentService.PolicyNamespace;
        XElement signer = Assert.Single(
            output.Root!.Element(ns + "Signers")!.Elements(ns + "Signer"));
        string signerId = signer.Attribute("ID")!.Value;
        string fileAttributeId =
            signer.Element(ns + "FileAttribRef")!.Attribute("RuleID")!.Value;
        Assert.NotEqual("ID_SIGNER_A", signerId);
        Assert.NotEqual("ID_FILEATTRIB_A", fileAttributeId);
        Assert.Contains(
            output.Root.Element(ns + "FileRules")!.Elements(ns + "FileAttrib"),
            attribute => attribute.Attribute("ID")?.Value == fileAttributeId);
        Assert.Contains(
            output.Root
                .Element(ns + "SigningScenarios")!
                .Descendants(ns + "AllowedSigner"),
            reference => reference.Attribute("SignerId")?.Value == signerId);
        Assert.Contains(
            output.Root.Element(ns + "CiSigners")!.Elements(ns + "CiSigner"),
            reference => reference.Attribute("SignerId")?.Value == signerId);
        Assert.Equal(
            "Contoso OPUS",
            signer.Element(ns + "CertOemID")?.Attribute("Value")?.Value);
        string[] ekuIds = signer.Elements(ns + "CertEKU")
            .Select(element => element.Attribute("ID")!.Value)
            .ToArray();
        Assert.Equal(2, ekuIds.Length);
        Assert.DoesNotContain("ID_EKU_A", ekuIds);
        Assert.DoesNotContain("ID_EKU_B", ekuIds);
        Assert.All(
            ekuIds,
            ekuId => Assert.Contains(
                output.Root.Element(ns + "EKUs")!.Elements(ns + "EKU"),
                eku => eku.Attribute("ID")?.Value == ekuId));
        Assert.Single(result.Changes);
        PolicyLogicalRule merged = Assert.Single(editor.Snapshot.Rules);
        Assert.Equal(PolicyRuleIdentity.FilePublisher, merged.Identity);
        Assert.Equal("Contoso OPUS", merged.Conditions["CertOemID"]);
        Assert.Equal("010A", merged.Conditions["CertEKU"]);
        Assert.Equal("010B", merged.Conditions["CertEKU[2]"]);
        Assert.NotNull(editor.Snapshot.FindEquivalent(candidate));
    }

    [Theory]
    [InlineData(SignerFileNameLevel.OriginalFileName, "FileName", "Contoso.exe", "original filename")]
    [InlineData(SignerFileNameLevel.InternalName, "InternalName", "Contoso", "internal name")]
    [InlineData(SignerFileNameLevel.FileDescription, "FileDescription", "Contoso application", "file description")]
    [InlineData(SignerFileNameLevel.ProductName, "ProductName", "Contoso Suite", "product name")]
    [InlineData(SignerFileNameLevel.PackageFamilyName, "PackageFamilyName", "Contoso.App_abc", "package family name")]
    [InlineData(SignerFileNameLevel.FilePath, "FilePath", @"C:\Contoso.exe", "file path")]
    public void SignerCandidateFactorySupportsEveryFileNameLevel(
        SignerFileNameLevel fileNameLevel,
        string attributeName,
        string attributeValue,
        string expectedDisplayName)
    {
        string packageVersionAttribute =
            fileNameLevel == SignerFileNameLevel.PackageFamilyName
                ? " PackageVersion=\"1.0.0.0\""
                : string.Empty;
        XDocument fragment = XDocument.Parse(
            $"""
             <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
               <FileRules>
                 <FileAttrib ID="ID_FILEATTRIB_A" {attributeName}="{attributeValue}" MinimumFileVersion="2.0.0.0"{packageVersionAttribute} />
               </FileRules>
               <Signers>
                 <Signer ID="ID_SIGNER_A" Name="Contoso">
                   <CertRoot Type="TBS" Value="AABBCC" />
                   <CertPublisher Value="Contoso Ltd" />
                   <FileAttribRef RuleID="ID_FILEATTRIB_A" />
                 </Signer>
               </Signers>
               <SigningScenarios>
                 <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_SOURCE">
                   <ProductSigners>
                     <AllowedSigners>
                       <AllowedSigner SignerId="ID_SIGNER_A" />
                     </AllowedSigners>
                   </ProductSigners>
                 </SigningScenario>
               </SigningScenarios>
             </SiPolicy>
             """);
        var result = new SignerRuleGenerationResult(
            SignerRuleLevel.FilePublisher,
            new PolicyRuleFragment(fragment),
            SignerCount: 1,
            HashRuleCount: 0,
            Diagnostic: null,
            fileNameLevel,
            FileAttributeCount: 1);

        PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
            @"C:\Contoso.exe",
            PolicyRuleScenario.Applications,
            result,
            new PolicyRuleGraphSnapshot([], []));

        Assert.True(candidate.CanApply, candidate.UnavailableReason);
        Assert.Equal(
            attributeValue,
            candidate.Conditions[$"FileAttribute[0].{attributeName}"]);
        Assert.Contains(
            expectedDisplayName,
            candidate.Effect,
            StringComparison.OrdinalIgnoreCase);
        if (fileNameLevel == SignerFileNameLevel.PackageFamilyName)
        {
            Assert.Contains("package version 1.0.0.0", candidate.Effect);
        }
    }

    [Fact]
    public void SignerCandidateFactoryRejectsFilePublisherWithoutFileAttribute()
    {
        XDocument fragment = XDocument.Parse(
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <FileRules />
              <Signers>
                <Signer ID="ID_SIGNER_A" Name="Contoso">
                  <CertRoot Type="TBS" Value="AABBCC" />
                  <CertPublisher Value="Contoso Ltd" />
                </Signer>
              </Signers>
              <SigningScenarios>
                <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_SOURCE">
                  <ProductSigners>
                    <AllowedSigners>
                      <AllowedSigner SignerId="ID_SIGNER_A" />
                    </AllowedSigners>
                  </ProductSigners>
                </SigningScenario>
              </SigningScenarios>
            </SiPolicy>
            """);
        var result = new SignerRuleGenerationResult(
            SignerRuleLevel.FilePublisher,
            new PolicyRuleFragment(fragment),
            SignerCount: 1,
            HashRuleCount: 0,
            Diagnostic:
                "ConfigCI generated a signer without the requested file attribute.",
            SignerFileNameLevel.PackageFamilyName,
            FileAttributeCount: 0);

        PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
            @"C:\Contoso.exe",
            PolicyRuleScenario.Applications,
            result,
            new PolicyRuleGraphSnapshot([], []));

        Assert.False(candidate.CanApply);
        Assert.Null(candidate.Fragment);
        Assert.Contains("without the requested file attribute", candidate.UnavailableReason);
    }

    [Fact]
    public void SignerCandidateFactoryRejectsConfigCiHashFallback()
    {
        XDocument fragment = XDocument.Parse(
            """
            <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
              <FileRules><Allow ID="ID_ALLOW_A" Hash="ABCDEF" /></FileRules>
              <Signers />
            </SiPolicy>
            """);
        var result = new SignerRuleGenerationResult(
            SignerRuleLevel.Publisher,
            new PolicyRuleFragment(fragment),
            SignerCount: 0,
            HashRuleCount: 1,
            Diagnostic: "ConfigCI generated a hash fallback.");

        PolicyRuleCandidate candidate = SignerRuleCandidateFactory.Create(
            @"C:\Contoso.exe",
            PolicyRuleScenario.Applications,
            result,
            new PolicyRuleGraphSnapshot([], []));

        Assert.False(candidate.CanApply);
        Assert.Null(candidate.Fragment);
        Assert.Contains("hash fallback", candidate.UnavailableReason);
    }

    [Fact]
    public void FileEvidenceAlwaysOffersExplicitHashAlternative()
    {
        using var testDirectory = new TestDirectory();
        string evidencePath = testDirectory.WriteText("unsigned.bin", "test evidence");
        var analyzer = new FileRuleCandidateAnalyzer();

        IReadOnlyList<PolicyRuleCandidate> candidates = analyzer.Analyze(
            evidencePath,
            PolicyRuleAction.Allow,
            new PolicyRuleGraphSnapshot([], []));

        PolicyRuleCandidate hash = Assert.Single(
            candidates,
            candidate => candidate.Identity == PolicyRuleIdentity.Hash);
        Assert.True(hash.CanApply);
        Assert.True(hash.IsRecommended);
        Assert.Equal(RuleUpdateResilience.Low, hash.UpdateResilience);
        Assert.Contains(hash.Concerns, concern => concern.Contains("replaced", StringComparison.Ordinal));
    }

    [Fact]
    public void ManualPathRejectsDriverScenario()
    {
        var analyzer = new FileRuleCandidateAnalyzer();

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => analyzer.CreateManual(
                PolicyRuleAction.Allow,
                PolicyRuleIdentity.FilePath,
                PolicyRuleScenario.Drivers,
                @"C:\Drivers\Contoso.sys",
                null,
                new PolicyRuleGraphSnapshot([], [])));

        Assert.Contains("applications only", exception.Message);
    }
}
