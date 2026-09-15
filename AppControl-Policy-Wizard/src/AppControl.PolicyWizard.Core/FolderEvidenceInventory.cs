using System.Diagnostics;

namespace AppControl.PolicyWizard.Core;

public enum FolderEvidenceKind
{
    Application,
    Driver,
    Script,
    Installer,
    Catalog
}

public sealed record FolderInventoryItem(
    string Path,
    string RelativePath,
    long Length,
    FolderEvidenceKind Kind,
    PolicyRuleScenario Scenario,
    string? OriginalFileName,
    string? ProductName,
    string? InternalName,
    string? FileDescription,
    string? FileVersion);

public sealed record FolderInventoryResult(
    string RootPath,
    IReadOnlyList<FolderInventoryItem> Items,
    int UnsupportedFileCount,
    int UnreadableFileCount,
    bool WasTruncated);

public sealed class FolderEvidenceInventoryScanner
{
    public const int DefaultMaximumFiles = 5000;

    private static readonly IReadOnlyDictionary<string, FolderEvidenceKind>
        SupportedExtensions =
            new Dictionary<string, FolderEvidenceKind>(
                StringComparer.OrdinalIgnoreCase)
            {
                [".exe"] = FolderEvidenceKind.Application,
                [".dll"] = FolderEvidenceKind.Application,
                [".ocx"] = FolderEvidenceKind.Application,
                [".cpl"] = FolderEvidenceKind.Application,
                [".scr"] = FolderEvidenceKind.Application,
                [".com"] = FolderEvidenceKind.Application,
                [".mui"] = FolderEvidenceKind.Application,
                [".mun"] = FolderEvidenceKind.Application,
                [".sys"] = FolderEvidenceKind.Driver,
                [".efi"] = FolderEvidenceKind.Driver,
                [".ps1"] = FolderEvidenceKind.Script,
                [".psm1"] = FolderEvidenceKind.Script,
                [".psd1"] = FolderEvidenceKind.Script,
                [".vbs"] = FolderEvidenceKind.Script,
                [".vbe"] = FolderEvidenceKind.Script,
                [".js"] = FolderEvidenceKind.Script,
                [".jse"] = FolderEvidenceKind.Script,
                [".wsf"] = FolderEvidenceKind.Script,
                [".wsh"] = FolderEvidenceKind.Script,
                [".cmd"] = FolderEvidenceKind.Script,
                [".bat"] = FolderEvidenceKind.Script,
                [".msi"] = FolderEvidenceKind.Installer,
                [".msp"] = FolderEvidenceKind.Installer,
                [".mst"] = FolderEvidenceKind.Installer,
                [".appx"] = FolderEvidenceKind.Installer,
                [".msix"] = FolderEvidenceKind.Installer,
                [".appxbundle"] = FolderEvidenceKind.Installer,
                [".msixbundle"] = FolderEvidenceKind.Installer,
                [".cat"] = FolderEvidenceKind.Catalog,
                [".p7x"] = FolderEvidenceKind.Catalog
            };

    public Task<FolderInventoryResult> ScanAsync(
        string folderPath,
        int maximumFiles = DefaultMaximumFiles,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(
            () => Scan(folderPath, maximumFiles, cancellationToken),
            cancellationToken);
    }

    public FolderInventoryResult Scan(
        string folderPath,
        int maximumFiles = DefaultMaximumFiles,
        CancellationToken cancellationToken = default)
    {
        if (maximumFiles <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumFiles),
                "The inventory limit must be greater than zero.");
        }

        string rootPath = Path.GetFullPath(folderPath);
        if (!Directory.Exists(rootPath))
        {
            throw new DirectoryNotFoundException(
                $"The selected folder was not found: {rootPath}");
        }

        var items = new List<FolderInventoryItem>();
        int unsupportedFileCount = 0;
        int unreadableFileCount = 0;
        bool wasTruncated = false;
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            ReturnSpecialDirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        foreach (string path in Directory.EnumerateFiles(rootPath, "*", options))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string extension = Path.GetExtension(path);
            if (!SupportedExtensions.TryGetValue(
                    extension,
                    out FolderEvidenceKind kind))
            {
                unsupportedFileCount++;
                continue;
            }

            if (items.Count >= maximumFiles)
            {
                wasTruncated = true;
                break;
            }

            try
            {
                var fileInfo = new FileInfo(path);
                FileVersionInfo versionInfo =
                    FileVersionInfo.GetVersionInfo(path);
                items.Add(
                    new FolderInventoryItem(
                        fileInfo.FullName,
                        Path.GetRelativePath(rootPath, fileInfo.FullName),
                        fileInfo.Length,
                        kind,
                        kind == FolderEvidenceKind.Driver
                            ? PolicyRuleScenario.Drivers
                            : PolicyRuleScenario.Applications,
                        Normalize(versionInfo.OriginalFilename),
                        Normalize(versionInfo.ProductName),
                        Normalize(versionInfo.InternalName),
                        Normalize(versionInfo.FileDescription),
                        Normalize(versionInfo.FileVersion)));
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException)
            {
                unreadableFileCount++;
            }
        }

        return new FolderInventoryResult(
            rootPath,
            items
                .OrderBy(item => item.RelativePath, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            unsupportedFileCount,
            unreadableFileCount,
            wasTruncated);
    }

    private static string? Normalize(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : value.Trim();
    }
}
