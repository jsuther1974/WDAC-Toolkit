using System.Xml.Linq;

namespace AppControl.PolicyWizard.Core;

public sealed class PolicyWorkflowService
{
    public const string InitialPolicyVersion = "1.0.0.0";

    private readonly IPolicyCompiler _compiler;
    private readonly PolicyDocumentService _documentService;
    private readonly IReadOnlyDictionary<PolicySourceKind, string> _templatePaths;

    public PolicyWorkflowService(
        IPolicyCompiler compiler,
        IReadOnlyDictionary<PolicySourceKind, string> templatePaths,
        PolicyDocumentService? documentService = null)
    {
        _compiler = compiler ?? throw new ArgumentNullException(nameof(compiler));
        _templatePaths = new Dictionary<PolicySourceKind, string>(
            templatePaths ?? throw new ArgumentNullException(nameof(templatePaths)));
        _documentService = documentService ?? new PolicyDocumentService();
    }

    public PolicySourceInfo InspectExistingPolicy(string policyPath)
    {
        return _documentService.InspectExistingPolicy(policyPath);
    }

    public async Task<PolicyBuildResult> BuildAsync(
        PolicyBuildRequest request,
        IProgress<PolicyBuildProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        progress?.Report(new PolicyBuildProgress(
            PolicyBuildStage.Validating,
            "Validating policy source and output."));

        if (string.IsNullOrWhiteSpace(request.PolicyName))
        {
            throw new InvalidDataException("The policy name cannot be empty.");
        }

        string sourcePath = ResolveSourcePath(request.SourceKind, request.ExistingPolicyPath);
        string fullOutputPath = Path.GetFullPath(request.OutputPath);
        ValidateOutputPath(sourcePath, fullOutputPath);

        XDocument sourceDocument = _documentService.Load(sourcePath);
        XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
        string? sourcePolicyId = sourceDocument.Root!.Element(policyNamespace + "PolicyID")?.Value;
        string? sourceBasePolicyId = sourceDocument.Root.Element(policyNamespace + "BasePolicyID")?.Value;
        string targetVersion = request.SourceKind == PolicySourceKind.ExistingPolicy
            ? PolicyVersion.Increment(
                sourceDocument.Root.Element(policyNamespace + "VersionEx")?.Value)
            : InitialPolicyVersion;

        string outputDirectory = Path.GetDirectoryName(fullOutputPath)
            ?? throw new InvalidDataException(
                "The policy output path does not contain a valid directory.");
        Directory.CreateDirectory(outputDirectory);

        string workingDirectory = Path.Combine(
            outputDirectory,
            $".wdac-build-{Guid.NewGuid():N}");
        string workingXmlPath = Path.Combine(workingDirectory, Path.GetFileName(fullOutputPath));
        bool resetPolicyIdentity = request.SourceKind != PolicySourceKind.ExistingPolicy;

        progress?.Report(new PolicyBuildProgress(
            PolicyBuildStage.Preparing,
            "Preparing an isolated policy working copy."));
        Directory.CreateDirectory(workingDirectory);

        try
        {
            File.Copy(sourcePath, workingXmlPath, overwrite: false);

            progress?.Report(new PolicyBuildProgress(
                PolicyBuildStage.Compiling,
                "Applying policy metadata and compiling with ConfigCI."));
            PolicyCompileResult compileResult = await _compiler.CompileAsync(
                new PolicyCompileRequest(
                    workingXmlPath,
                    request.PolicyName,
                    resetPolicyIdentity,
                    targetVersion),
                cancellationToken);

            ValidateCompileResult(
                compileResult,
                targetVersion,
                resetPolicyIdentity,
                sourcePolicyId,
                sourceBasePolicyId);
            ValidateCompiledDocument(
                workingXmlPath,
                compileResult,
                targetVersion,
                resetPolicyIdentity,
                sourcePolicyId,
                sourceBasePolicyId);

            string compiledBinaryPath = Path.GetFullPath(compileResult.BinaryPath);
            if (!string.Equals(
                    Path.GetDirectoryName(compiledBinaryPath),
                    workingDirectory,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new PolicyBuildException(
                    "ConfigCI returned a binary policy outside the isolated working directory.");
            }

            if (!File.Exists(compiledBinaryPath))
            {
                throw new PolicyBuildException(
                    $"ConfigCI did not create the expected binary policy '{compiledBinaryPath}'.");
            }

            string finalBinaryPath = Path.Combine(
                outputDirectory,
                Path.GetFileName(compiledBinaryPath));
            if (File.Exists(finalBinaryPath))
            {
                throw new IOException($"A binary policy already exists at '{finalBinaryPath}'.");
            }

            progress?.Report(new PolicyBuildProgress(
                PolicyBuildStage.Finalizing,
                "Moving completed policy files into place."));
            File.Move(compiledBinaryPath, finalBinaryPath);
            try
            {
                File.Move(workingXmlPath, fullOutputPath);
            }
            catch (IOException)
            {
                File.Delete(finalBinaryPath);
                throw;
            }
            catch (UnauthorizedAccessException)
            {
                File.Delete(finalBinaryPath);
                throw;
            }

            return new PolicyBuildResult(
                fullOutputPath,
                finalBinaryPath,
                compileResult.PolicyID,
                compileResult.BasePolicyID,
                compileResult.Version);
        }
        finally
        {
            if (Directory.Exists(workingDirectory))
            {
                Directory.Delete(workingDirectory, recursive: true);
            }
        }
    }

    private string ResolveSourcePath(
        PolicySourceKind sourceKind,
        string? existingPolicyPath)
    {
        if (sourceKind == PolicySourceKind.ExistingPolicy)
        {
            if (string.IsNullOrWhiteSpace(existingPolicyPath))
            {
                throw new InvalidDataException(
                    "Select an existing App Control policy before continuing.");
            }

            string fullPath = Path.GetFullPath(existingPolicyPath);
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException(
                    "The selected policy file could not be found.",
                    fullPath);
            }

            return fullPath;
        }

        if (!_templatePaths.TryGetValue(sourceKind, out string? templatePath))
        {
            throw new InvalidDataException($"Unknown policy source: {sourceKind}");
        }

        string fullTemplatePath = Path.GetFullPath(templatePath);
        if (!File.Exists(fullTemplatePath))
        {
            throw new FileNotFoundException(
                $"The packaged policy template '{Path.GetFileName(fullTemplatePath)}' could not be found.",
                fullTemplatePath);
        }

        return fullTemplatePath;
    }

    private static void ValidateOutputPath(string sourcePath, string fullOutputPath)
    {
        if (!string.Equals(
                Path.GetExtension(fullOutputPath),
                ".xml",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The policy output file must use the .xml extension.");
        }

        if (string.Equals(sourcePath, fullOutputPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("The output file must be different from the source policy.");
        }

        if (File.Exists(fullOutputPath))
        {
            throw new IOException($"A policy file already exists at '{fullOutputPath}'.");
        }
    }

    private static void ValidateCompileResult(
        PolicyCompileResult result,
        string expectedVersion,
        bool resetPolicyIdentity,
        string? sourcePolicyId,
        string? sourceBasePolicyId)
    {
        if (string.IsNullOrWhiteSpace(result.BinaryPath))
        {
            throw new PolicyBuildException("ConfigCI did not return a binary policy path.");
        }

        if (!string.Equals(result.Version, expectedVersion, StringComparison.Ordinal))
        {
            throw new PolicyBuildException(
                $"ConfigCI returned version '{result.Version}' instead of '{expectedVersion}'.");
        }

        if (resetPolicyIdentity)
        {
            if (string.IsNullOrWhiteSpace(result.PolicyID)
                || string.IsNullOrWhiteSpace(result.BasePolicyID))
            {
                throw new PolicyBuildException(
                    "ConfigCI did not return complete policy identity information.");
            }

            return;
        }

        if (!string.Equals(result.PolicyID, sourcePolicyId, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                result.BasePolicyID,
                sourceBasePolicyId,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new PolicyBuildException(
                "ConfigCI changed the identity of the existing policy.");
        }
    }

    private void ValidateCompiledDocument(
        string workingXmlPath,
        PolicyCompileResult result,
        string expectedVersion,
        bool resetPolicyIdentity,
        string? sourcePolicyId,
        string? sourceBasePolicyId)
    {
        XDocument compiledDocument = _documentService.Load(workingXmlPath);
        XNamespace policyNamespace = PolicyDocumentService.PolicyNamespace;
        XElement root = compiledDocument.Root!;
        string? documentPolicyId = root.Element(policyNamespace + "PolicyID")?.Value;
        string? documentBasePolicyId = root.Element(policyNamespace + "BasePolicyID")?.Value;
        string? documentVersion = root.Element(policyNamespace + "VersionEx")?.Value;

        if (!string.Equals(documentVersion, expectedVersion, StringComparison.Ordinal)
            || !string.Equals(
                documentVersion,
                result.Version,
                StringComparison.Ordinal))
        {
            throw new PolicyBuildException(
                "The compiled XML policy does not contain the expected version.");
        }

        if (!string.Equals(
                documentPolicyId,
                result.PolicyID,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                documentBasePolicyId,
                result.BasePolicyID,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new PolicyBuildException(
                "The compiled XML policy identity does not match the compiler result.");
        }

        if (!resetPolicyIdentity
            && (!string.Equals(
                    documentPolicyId,
                    sourcePolicyId,
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    documentBasePolicyId,
                    sourceBasePolicyId,
                    StringComparison.OrdinalIgnoreCase)))
        {
            throw new PolicyBuildException(
                "The compiled XML policy changed the existing policy identity.");
        }
    }
}
