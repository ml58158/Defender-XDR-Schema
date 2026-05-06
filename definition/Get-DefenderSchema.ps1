<#
.SYNOPSIS
    Extracts full Advanced Hunting schema documentation (Fields + ActionTypes + Sample Queries)
    from the Defender XDR internal huntingService API.

.DESCRIPTION
    Discovered API endpoint (used by the portal UI):
      GET https://security.microsoft.com/apiproxy/mtp/huntingService/documentation/TableDocumentation/{TableName}

    Backend:
      https://m365d-hunting-api-prd-{region}.securitycenter.windows.com/api/ine/huntingservice/documentation/TableDocumentation/{TableName}

    This endpoint returns:
      - Fields[]       -> Column name + description (richer than public docs)
      - ActionTypes[]  -> Full enumeration with Name + Description (THE MISSING DATA)
      - Queries[]      -> Sample KQL queries per table
      - Metadata       -> HotDays, ColdDays, TableType, Tags, etc.

    Authentication: Requires sccauth cookie + x-xsrf-token header from an active portal session.
    Rate Limit: 250 req/min (x-rate-limit-limit: 1m, x-rate-limit-remaining header)

.PARAMETER SessionCookie
    The 'sccauth' cookie value from an active security.microsoft.com session.
    DevTools -> Application -> Cookies -> sccauth

.PARAMETER XsrfToken
    The 'XSRF-TOKEN' cookie value from the same session.
    DevTools -> Application -> Cookies -> XSRF-TOKEN
    NOTE: This value is URL-encoded. Copy it as-is, the script will decode it.

.PARAMETER TenantId
    Your Entra ID tenant GUID.

.PARAMETER OutputPath
    Output directory for generated files. Default: ./DefenderSchema

.PARAMETER Tables
    Optional array of specific table names to pull. If omitted, pulls ALL known tables.

.EXAMPLE
    # Quick grab from DevTools -> Application -> Cookies on security.microsoft.com:
    #   1. Copy 'sccauth' cookie value
    #   2. Copy 'XSRF-TOKEN' cookie value
    #   3. Run:
    .\Get-DefenderSchema.ps1 `
        -SessionCookie "wN6c4hZ-x7II..." `
        -XsrfToken "CfDJ8N..." `
        -TenantId "27c9901b-9650-4f50-b9b3-38611d797f9f"

.NOTES
    Author: Generated for red team schema documentation
    The cookies are session-bound and will expire. Refresh from the portal as needed.
    Compatible with PowerShell 5.1+ and PowerShell 7+.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SessionCookie,

    [Parameter(Mandatory = $true)]
    [string]$XsrfToken,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./DefenderSchema",

    [Parameter(Mandatory = $false)]
    [string[]]$Tables
)

$ErrorActionPreference = "Stop"

# --- All known Advanced Hunting tables ---
$AllTables = @(
    "AADSignInEventsBeta",
    "AADSpnSignInEventsBeta",
    "AlertEvidence",
    "AlertInfo",
    "BehaviorEntities",
    "BehaviorInfo",
    "CampaignInfo",
    "CloudAppEvents",
    "CloudAuditEvents",
    "CloudProcessEvents",
    "CloudStorageAggregatedEvents",
    "DataSecurityBehaviors",
    "DataSecurityEvents",
    "DeviceBaselineComplianceAssessment",
    "DeviceBaselineComplianceAssessmentKB",
    "DeviceBaselineComplianceProfiles",
    "DeviceEvents",
    "DeviceFileCertificateInfo",
    "DeviceFileEvents",
    "DeviceImageLoadEvents",
    "DeviceInfo",
    "DeviceLogonEvents",
    "DeviceNetworkEvents",
    "DeviceNetworkInfo",
    "DeviceProcessEvents",
    "DeviceRegistryEvents",
    "DeviceTvmBrowserExtensions",
    "DeviceTvmBrowserExtensionsKB",
    "DeviceTvmCertificateInfo",
    "DeviceTvmHardwareFirmware",
    "DeviceTvmInfoGathering",
    "DeviceTvmInfoGatheringKB",
    "DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSecureConfigurationAssessmentKB",
    "DeviceTvmSoftwareEvidenceBeta",
    "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareVulnerabilitiesKB",
    "DisruptionAndResponseEvents",
    "EmailAttachmentInfo",
    "EmailEvents",
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "EntraIdSignInEvents",
    "EntraIdSpnSignInEvents",
    "ExposureGraphEdges",
    "ExposureGraphNodes",
    "FileMaliciousContentInfo",
    "GraphApiAuditEvents",
    "IdentityAccountInfo",
    "IdentityDirectoryEvents",
    "IdentityEvents",
    "IdentityInfo",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "MessageEvents",
    "MessagePostDeliveryEvents",
    "MessageUrlInfo",
    "OAuthAppInfo",
    "UrlClickEvents"
)

# Use provided tables or all
$TargetTables = if ($Tables) { $Tables } else { $AllTables }

# --- Setup ---
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$baseUrl = "https://security.microsoft.com/apiproxy/mtp/huntingService/documentation/TableDocumentation"

# URL-decode the XSRF token if it's encoded (common when copying from browser)
# Try .NET URI decode first (always available), then System.Web if loaded
try {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $decodedXsrf = [System.Web.HttpUtility]::UrlDecode($XsrfToken)
} catch {
    $decodedXsrf = [System.Uri]::UnescapeDataString($XsrfToken)
}
if (-not $decodedXsrf) {
    $decodedXsrf = $XsrfToken
}

# --- CRITICAL: PS 5.1 strips the Cookie header from -Headers silently ---
# Must use a WebRequestSession with CookieContainer instead
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$cookieUri = [System.Uri]"https://security.microsoft.com"

$sccauthCookie = New-Object System.Net.Cookie("sccauth", $SessionCookie, "/", "security.microsoft.com")
$session.Cookies.Add($cookieUri, $sccauthCookie)

$xsrfCookie = New-Object System.Net.Cookie("XSRF-TOKEN", $XsrfToken, "/", "security.microsoft.com")
$session.Cookies.Add($cookieUri, $xsrfCookie)

# Headers that are NOT cookies (these pass through fine)
$headers = @{
    "accept"          = "application/json, text/plain, */*"
    "accept-language" = "en-us"
    "x-xsrf-token"   = $decodedXsrf
    "tenant-id"       = $TenantId
}

# --- UTC timestamp helper (PS 5.1 compatible) ---
function Get-UtcTimestamp {
    return [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
}

# --- Pull schema for each table ---
Write-Host "`n=== Defender XDR Schema Extractor ===" -ForegroundColor Cyan
Write-Host "Target: $($TargetTables.Count) tables" -ForegroundColor Cyan
Write-Host "Output: $OutputPath`n" -ForegroundColor Cyan

$allSchemas = @()
$failedTables = @()
$tableIndex = 0

foreach ($table in $TargetTables) {
    $tableIndex++
    $pct = [math]::Round(($tableIndex / $TargetTables.Count) * 100)
    Write-Host "[$tableIndex/$($TargetTables.Count)] ($pct%) $table... " -NoNewline -ForegroundColor Yellow

    try {
        $response = Invoke-RestMethod -Uri "$baseUrl/$table" -Headers $headers -Method Get -WebSession $session
        $fieldCount = ($response.Fields | Measure-Object).Count
        $atCount = ($response.ActionTypes | Measure-Object).Count
        $qCount = ($response.Queries | Measure-Object).Count

        Write-Host "$fieldCount fields" -NoNewline -ForegroundColor Green
        if ($atCount -gt 0) {
            Write-Host ", $atCount ActionTypes" -NoNewline -ForegroundColor Magenta
        }
        if ($qCount -gt 0) {
            Write-Host ", $qCount queries" -NoNewline -ForegroundColor DarkCyan
        }
        Write-Host ""

        # Bail early if first table returns 0 fields (auth issue)
        if ($tableIndex -eq 1 -and $fieldCount -eq 0) {
            Write-Host "`n[!] First table returned 0 fields - authentication likely failed." -ForegroundColor Red
            Write-Host "    Verify your sccauth and XSRF-TOKEN cookies are fresh." -ForegroundColor Red
            Write-Host "    Try refreshing the portal page and re-copying both cookies." -ForegroundColor Red
            Write-Host "`n    To debug, open DevTools -> Network tab in the portal," -ForegroundColor Yellow
            Write-Host "    click a table name in the schema panel, and check the" -ForegroundColor Yellow
            Write-Host "    request headers on the TableDocumentation call.`n" -ForegroundColor Yellow
            break
        }

        # Save individual JSON
        $response | ConvertTo-Json -Depth 10 | Out-File "$OutputPath/$table.json" -Encoding utf8

        $allSchemas += [PSCustomObject]@{
            Name         = $response.Name
            Description  = $response.Description
            TableType    = $response.TableType
            HotDays      = $response.HotDays
            ColdDays     = $response.ColdDays
            Fields       = $response.Fields
            ActionTypes  = $response.ActionTypes
            Queries      = $response.Queries
        }
    }
    catch {
        Write-Host "FAILED - $($_.Exception.Message)" -ForegroundColor Red
        $failedTables += $table
    }

    # Respect rate limit (250/min = ~240ms between requests, using 300ms for safety)
    Start-Sleep -Milliseconds 300
}

if ($allSchemas.Count -eq 0) {
    Write-Host "`nNo data retrieved. Exiting." -ForegroundColor Red
    exit 1
}

# --- Save combined JSON ---
$combinedJson = $allSchemas | ConvertTo-Json -Depth 10
$combinedJson | Out-File "$OutputPath/_AllTables.json" -Encoding utf8
Write-Host "`nCombined JSON: $OutputPath/_AllTables.json" -ForegroundColor Green

# --- Generate Markdown Reference ---
$genTime = Get-UtcTimestamp
$md = @()
$md += "# Microsoft Defender XDR - Advanced Hunting Complete Schema Reference"
$md += ""
$md += "> **Source:** Defender XDR huntingService internal API"
$md += "> **Endpoint:** ``GET /apiproxy/mtp/huntingService/documentation/TableDocumentation/{TableName}``  "
$md += "> **Generated:** $genTime  "
$md += "> **Tenant:** ``$TenantId``  "
$md += "> **Tables:** $($allSchemas.Count) successfully pulled"
$md += ""
$md += "---"
$md += ""

# Table of Contents
$md += "## Table of Contents"
$md += ""
foreach ($schema in $allSchemas) {
    $anchor = $schema.Name.ToLower()
    $atCount = ($schema.ActionTypes | Measure-Object).Count
    $marker = if ($atCount -gt 0) { " ($atCount ActionTypes)" } else { "" }
    $md += "- [$($schema.Name)](#$anchor)$marker"
}
$md += ""
$md += "---"
$md += ""

# Per-table sections
foreach ($schema in $allSchemas) {
    $md += "## $($schema.Name)"
    $md += ""
    $md += "> $($schema.Description)"
    $md += ""

    $hotDays = if ($schema.HotDays) { $schema.HotDays } else { "N/A" }
    $coldDays = if ($schema.ColdDays) { $schema.ColdDays } else { "N/A" }
    $md += "**Retention:** Hot: ${hotDays}d | Cold: ${coldDays}d | **Type:** $($schema.TableType)"
    $md += ""

    # Columns
    $md += "### Columns"
    $md += ""
    $md += "| Column Name | Description |"
    $md += "|---|---|"
    foreach ($field in $schema.Fields) {
        $desc = if ($field.Description) { $field.Description.Replace("|", "\|") } else { "" }
        $md += "| ``$($field.Name)`` | $desc |"
    }
    $md += ""

    # ActionTypes
    $atCount = ($schema.ActionTypes | Measure-Object).Count
    if ($atCount -gt 0) {
        $md += "### ActionTypes ($atCount)"
        $md += ""
        $md += "| ActionType | Description |"
        $md += "|---|---|"
        foreach ($at in $schema.ActionTypes) {
            $desc = if ($at.Description) { $at.Description.Replace("|", "\|") } else { "" }
            $md += "| ``$($at.Name)`` | $desc |"
        }
        $md += ""
    }

    # Sample Queries
    $qCount = ($schema.Queries | Measure-Object).Count
    if ($qCount -gt 0) {
        $md += "### Sample Queries"
        $md += ""
        foreach ($q in $schema.Queries) {
            $md += "**$($q.Name)** - $($q.Description)"
            $md += ""
            $md += "``````kql"
            $md += $q.QueryText
            $md += "``````"
            $md += ""
        }
    }
}

# Write markdown
$mdContent = $md -join "`n"
$mdContent | Out-File "$OutputPath/DefenderXDR_SchemaReference.md" -Encoding utf8
Write-Host "Markdown: $OutputPath/DefenderXDR_SchemaReference.md" -ForegroundColor Green

# --- Generate ActionTypes-only reference ---
$atMd = @()
$atMd += "# Defender XDR - ActionType Quick Reference"
$atMd += ""
$atMd += "> Generated: $genTime"
$atMd += ""
$atMd += "---"
$atMd += ""

$totalActionTypes = 0
foreach ($schema in $allSchemas) {
    $atCount = ($schema.ActionTypes | Measure-Object).Count
    if ($atCount -gt 0) {
        $totalActionTypes += $atCount
        $atMd += "## $($schema.Name) ($atCount)"
        $atMd += ""
        $atMd += "| ActionType | Description |"
        $atMd += "|---|---|"
        foreach ($at in $schema.ActionTypes) {
            $desc = if ($at.Description) { $at.Description.Replace("|", "\|") } else { "" }
            $atMd += "| ``$($at.Name)`` | $desc |"
        }
        $atMd += ""
    }
}

$atMdContent = $atMd -join "`n"
$atMdContent | Out-File "$OutputPath/ActionTypes_Reference.md" -Encoding utf8
Write-Host "ActionTypes: $OutputPath/ActionTypes_Reference.md" -ForegroundColor Green

# --- Summary ---
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Tables pulled:    $($allSchemas.Count)" -ForegroundColor Green
Write-Host "Total ActionTypes: $totalActionTypes" -ForegroundColor Magenta
if ($failedTables.Count -gt 0) {
    Write-Host "Failed tables:    $($failedTables -join ', ')" -ForegroundColor Red
}
Write-Host "`nOutput files:" -ForegroundColor Cyan
Write-Host "  $OutputPath/_AllTables.json              (combined raw JSON)"
Write-Host "  $OutputPath/DefenderXDR_SchemaReference.md (full reference)"
Write-Host "  $OutputPath/ActionTypes_Reference.md       (ActionTypes only)"
Write-Host "  $OutputPath/{TableName}.json               (individual table JSONs)"
Write-Host "`nDone!" -ForegroundColor Green