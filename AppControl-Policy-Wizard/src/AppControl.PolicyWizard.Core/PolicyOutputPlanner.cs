namespace AppControl.PolicyWizard.Core;

public static class PolicyOutputPlanner
{
    public static string SanitizeFileName(string value)
    {
        foreach (char character in Path.GetInvalidFileNameChars())
        {
            value = value.Replace(character, '_');
        }

        return value.Trim();
    }

    public static string CreateDefaultBaseName(
        PolicySourceKind sourceKind,
        PolicySourceInfo? existingPolicy,
        DateOnly currentDate)
    {
        if (sourceKind == PolicySourceKind.ExistingPolicy)
        {
            if (existingPolicy is null)
            {
                throw new InvalidDataException(
                    "Select an existing App Control policy before creating its output name.");
            }

            string sourceStem = GetExistingPolicyOutputStem(existingPolicy);
            return $"{sourceStem}_v{existingPolicy.NextVersion}";
        }

        string templateStem = sourceKind switch
        {
            PolicySourceKind.SignedAndReputable => "SignedAndReputable",
            PolicySourceKind.WindowsOnly => "WindowsOnly",
            _ => throw new InvalidDataException($"Unknown policy source: {sourceKind}")
        };

        return $"{templateStem}_{currentDate:yyyy-MM-dd}";
    }

    public static string GetAvailableOutputPath(
        string appControlDirectory,
        string baseName,
        bool useDedicatedDirectory)
    {
        string safeBaseName = SanitizeFileName(baseName);
        if (string.IsNullOrWhiteSpace(safeBaseName))
        {
            throw new InvalidDataException("The policy output file name cannot be empty.");
        }

        return useDedicatedDirectory
            ? GetAvailableDedicatedOutputPath(appControlDirectory, safeBaseName)
            : GetAvailableFlatOutputPath(appControlDirectory, safeBaseName);
    }

    private static string GetExistingPolicyOutputStem(PolicySourceInfo policy)
    {
        string sourceStem = SanitizeFileName(Path.GetFileNameWithoutExtension(policy.Path));
        string versionSuffix = $"_v{policy.Version}";

        return sourceStem.EndsWith(versionSuffix, StringComparison.OrdinalIgnoreCase)
            ? sourceStem[..^versionSuffix.Length]
            : sourceStem;
    }

    private static string GetAvailableFlatOutputPath(string outputDirectory, string baseName)
    {
        string candidate = Path.Combine(outputDirectory, $"{baseName}.xml");
        int suffix = 2;

        while (File.Exists(candidate))
        {
            candidate = Path.Combine(outputDirectory, $"{baseName}_{suffix}.xml");
            suffix++;
        }

        return candidate;
    }

    private static string GetAvailableDedicatedOutputPath(string appControlDirectory, string baseName)
    {
        string outputDirectory = Path.Combine(appControlDirectory, baseName);
        int suffix = 2;

        while (Directory.Exists(outputDirectory))
        {
            outputDirectory = Path.Combine(appControlDirectory, $"{baseName}_{suffix}");
            suffix++;
        }

        return Path.Combine(outputDirectory, $"{Path.GetFileName(outputDirectory)}.xml");
    }
}
