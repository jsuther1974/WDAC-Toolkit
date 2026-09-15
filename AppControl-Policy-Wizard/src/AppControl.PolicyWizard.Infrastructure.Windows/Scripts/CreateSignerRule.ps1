[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$SourcePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("PcaCertificate", "Publisher", "FilePublisher")]
    [string]$Level,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Allow", "Deny")]
    [string]$Action,

    [ValidateSet(
        "OriginalFileName",
        "InternalName",
        "FileDescription",
        "ProductName",
        "PackageFamilyName",
        "FilePath")]
    [string]$SpecificFileNameLevel
)

$ErrorActionPreference = "Stop"

Import-Module ConfigCI -ErrorAction Stop

# ConfigCI can throw a one-time initialization error on the first
# New-CIPolicyRule invocation in Windows PowerShell 5.1.
try
{
    New-CIPolicyRule -Level Publisher -DriverFilePath $SourcePath -Fallback Hash | Out-Null
}
catch
{
}

$ruleParameters = @{
    Level = $Level
    DriverFilePath = $SourcePath
    Fallback = "Hash"
}
if (-not [string]::IsNullOrWhiteSpace($SpecificFileNameLevel))
{
    if ($Level -ne "FilePublisher")
    {
        throw "SpecificFileNameLevel is valid only for FilePublisher rules."
    }

    $ruleParameters.SpecificFileNameLevel = $SpecificFileNameLevel
}
if ($Action -eq "Deny")
{
    $ruleParameters.Deny = $true
}

$rules = New-CIPolicyRule @ruleParameters
if ($null -eq $rules)
{
    throw "ConfigCI did not return a rule."
}

New-CIPolicy -Rules $rules -FilePath $OutputPath | Out-Null

[xml]$policy = Get-Content -LiteralPath $OutputPath
$signerCount = @($policy.SiPolicy.Signers.Signer).Count
$fileAttributeCount = @($policy.SiPolicy.FileRules.FileAttrib).Count
$hashRuleCount = @(
    $policy.SiPolicy.FileRules.ChildNodes |
        Where-Object { $null -ne $_.Hash }
).Count
$diagnostic = if ($signerCount -eq 0 -and $hashRuleCount -gt 0)
{
    "ConfigCI generated hash fallback rules instead of the requested signer rule."
}
elseif ($signerCount -eq 0)
{
    "ConfigCI did not generate a signer rule."
}
elseif ($Level -eq "FilePublisher" -and $fileAttributeCount -eq 0)
{
    "ConfigCI generated a signer without the requested file attribute."
}
else
{
    $null
}

[pscustomobject]@{
    SignerCount = $signerCount
    FileAttributeCount = $fileAttributeCount
    HashRuleCount = $hashRuleCount
    Diagnostic = $diagnostic
} | ConvertTo-Json -Compress
