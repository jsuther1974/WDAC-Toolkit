[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$AsJson
)

$ErrorActionPreference = "Stop"

$ledgerPath = Join-Path $PSScriptRoot "capabilities.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$capabilities = @($ledger.capabilities)

$summary = [ordered]@{}
foreach ($status in $ledger.statusOrder)
{
    $summary[$status] = @($capabilities | Where-Object migrationStatus -eq $status).Count
}

if ($AsJson)
{
    [pscustomobject]@{
        AsOf         = $ledger.asOf
        Total        = $capabilities.Count
        Summary      = [pscustomobject]$summary
        Capabilities = $capabilities
    } | ConvertTo-Json -Depth 8
    return
}

$capabilities |
    Sort-Object priority, area, name |
    Select-Object priority, area, name, migrationStatus, decisionStatus |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Migration burndown as of $($ledger.asOf)"
foreach ($entry in $summary.GetEnumerator())
{
    Write-Host ("  {0,-16} {1,3}" -f $entry.Key, $entry.Value)
}
