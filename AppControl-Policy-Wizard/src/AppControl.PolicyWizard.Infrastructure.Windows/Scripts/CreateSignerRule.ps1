[CmdletBinding(DefaultParameterSetName = "Single")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Single")]
    [string]$SourcePath,

    [Parameter(Mandatory = $true, ParameterSetName = "Single")]
    [string]$OutputPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Single")]
    [ValidateSet("PcaCertificate", "Publisher", "FilePublisher")]
    [string]$Level,

    [Parameter(Mandatory = $true, ParameterSetName = "Single")]
    [ValidateSet("Allow", "Deny")]
    [string]$Action,

    [Parameter(ParameterSetName = "Single")]
    [ValidateSet(
        "OriginalFileName",
        "InternalName",
        "FileDescription",
        "ProductName",
        "PackageFamilyName",
        "FilePath")]
    [string]$SpecificFileNameLevel,

    [Parameter(Mandatory = $true, ParameterSetName = "Batch")]
    [string]$RequestPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Batch")]
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"

function New-SignerRuleResult
{
    param (
        [Parameter(Mandatory = $true)]
        [int]$Index,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Request,

        [Parameter(Mandatory = $true)]
        [string]$ResultPath
    )

    $ruleParameters = @{
        Level = [string]$Request.Level
        DriverFilePath = [string]$Request.SourcePath
        Fallback = "Hash"
    }
    if (-not [string]::IsNullOrWhiteSpace(
            [string]$Request.SpecificFileNameLevel))
    {
        if ([string]$Request.Level -ne "FilePublisher")
        {
            throw "SpecificFileNameLevel is valid only for FilePublisher rules."
        }

        $ruleParameters.SpecificFileNameLevel =
            [string]$Request.SpecificFileNameLevel
    }
    if ([string]$Request.Action -eq "Deny")
    {
        $ruleParameters.Deny = $true
    }

    $rules = New-CIPolicyRule @ruleParameters
    if ($null -eq $rules)
    {
        throw "ConfigCI did not return a rule."
    }

    New-CIPolicy -Rules $rules -FilePath $ResultPath | Out-Null

    [xml]$policy = Get-Content -LiteralPath $ResultPath
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
    elseif ([string]$Request.Level -eq "FilePublisher" -and
        $fileAttributeCount -eq 0)
    {
        "ConfigCI generated a signer without the requested file attribute."
    }
    else
    {
        $null
    }

    [pscustomobject]@{
        Index = $Index
        OutputFileName = [System.IO.Path]::GetFileName($ResultPath)
        SignerCount = $signerCount
        FileAttributeCount = $fileAttributeCount
        HashRuleCount = $hashRuleCount
        Diagnostic = $diagnostic
        Error = $null
    }
}

Import-Module ConfigCI -ErrorAction Stop

if ($PSCmdlet.ParameterSetName -eq "Batch")
{
    $parsedRequests = Get-Content -LiteralPath $RequestPath -Raw |
        ConvertFrom-Json
    $requests = @()
    foreach ($parsedRequest in $parsedRequests)
    {
        $requests += $parsedRequest
    }
    if ($requests.Count -eq 0)
    {
        throw "At least one signer-generation request is required."
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force |
        Out-Null

    # ConfigCI can throw a one-time initialization error on the first
    # New-CIPolicyRule invocation in Windows PowerShell 5.1.
    try
    {
        New-CIPolicyRule `
            -Level Publisher `
            -DriverFilePath ([string]$requests[0].SourcePath) `
            -Fallback Hash |
            Out-Null
    }
    catch
    {
    }

    $results = for ($index = 0; $index -lt $requests.Count; $index++)
    {
        $request = $requests[$index]
        $resultPath = Join-Path $OutputDirectory (
            "{0:D5}.xml" -f $index)
        try
        {
            New-SignerRuleResult `
                -Index $index `
                -Request $request `
                -ResultPath $resultPath
        }
        catch
        {
            [pscustomobject]@{
                Index = $index
                OutputFileName = $null
                SignerCount = 0
                FileAttributeCount = 0
                HashRuleCount = 0
                Diagnostic = $null
                Error = $_.Exception.Message
            }
        }
    }

    [pscustomobject]@{
        Results = @($results)
    } | ConvertTo-Json -Compress -Depth 4
    return
}

$singleRequest = [pscustomobject]@{
    SourcePath = $SourcePath
    Level = $Level
    Action = $Action
    SpecificFileNameLevel = $SpecificFileNameLevel
}

# Retain the single-request entry point for diagnostics and compatibility.
try
{
    New-CIPolicyRule `
        -Level Publisher `
        -DriverFilePath $SourcePath `
        -Fallback Hash |
        Out-Null
}
catch
{
}

New-SignerRuleResult `
    -Index 0 `
    -Request $singleRequest `
    -ResultPath $OutputPath |
    Select-Object `
        SignerCount,
        FileAttributeCount,
        HashRuleCount,
        Diagnostic |
    ConvertTo-Json -Compress
