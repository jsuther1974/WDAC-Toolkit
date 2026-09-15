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
    [string]$Action
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
else
{
    $null
}

[pscustomobject]@{
    SignerCount = $signerCount
    HashRuleCount = $hashRuleCount
    Diagnostic = $diagnostic
} | ConvertTo-Json -Compress
