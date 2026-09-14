[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$XmlPath,

    [Parameter(Mandatory = $true)]
    [string]$PolicyName,

    [Parameter(Mandatory = $false)]
    [string]$Version = "1.0.0.0",

    [Parameter(Mandatory = $false)]
    [switch]$ResetPolicyIdentity
)

$ErrorActionPreference = "Stop"

Import-Module ConfigCI -ErrorAction Stop

if ($ResetPolicyIdentity)
{
    Set-CIPolicyIdInfo -FilePath $XmlPath -PolicyName $PolicyName -ResetPolicyID | Out-Null
}

Set-CIPolicyVersion -FilePath $XmlPath -Version $Version | Out-Null

[xml]$Policy = Get-Content -LiteralPath $XmlPath
$PolicyID = [string]$Policy.SiPolicy.PolicyID
$BinaryFileName = if ([string]::IsNullOrWhiteSpace($PolicyID)) { "SiPolicy.p7b" } else { $PolicyID + ".cip" }
$BinaryPath = Join-Path (Split-Path -Parent $XmlPath) $BinaryFileName

ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath $BinaryPath | Out-Null

[pscustomobject]@{
    PolicyID     = $Policy.SiPolicy.PolicyID
    BasePolicyID = $Policy.SiPolicy.BasePolicyID
    Version      = $Policy.SiPolicy.VersionEx
    BinaryPath   = $BinaryPath
} | ConvertTo-Json -Compress
