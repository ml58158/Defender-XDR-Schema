# Defender XDR Advanced Hunting — Complete Schema Dataset

A schema-aware dataset and Claude AI skill for Microsoft Defender XDR Advanced Hunting. Provides the **complete** table schema including the full `ActionType` enumeration that Microsoft's public documentation omits.

## The Problem

Microsoft's public Advanced Hunting documentation lists columns and data types for each table, but the `ActionType` column — arguably the most important field for detection engineering — is documented with nothing more than:

> *"Type of activity that triggered the event. See the in-portal schema reference for details."*

The actual `ActionType` values (e.g., `ProcessCreated`, `CreateRemoteThreadApiCall`, `QueueUserApcRemoteApiCall`, `DnsQueryResponse`, `FirewallInboundConnectionBlocked`, etc.) and their descriptions are **only visible inside the Defender XDR portal UI**. They are not available in any public API, documentation page, or GitHub repo. This means:

- KQL query authors have to manually browse the portal schema panel to discover valid values
- AI assistants hallucinate ActionType values because no machine-readable reference exists
- Detection engineers can't programmatically enumerate the full attack surface of a table
- Training content and lab environments can't reference authoritative ActionType lists

This project solves that by extracting the complete schema — fields, ActionTypes, sample queries, and retention metadata — from the internal API that powers the portal's schema panel.

## Data Sources

### 1. Internal huntingService API (Primary)

The Defender XDR portal loads schema documentation from an undocumented internal endpoint:

```
GET https://security.microsoft.com/apiproxy/mtp/huntingService/documentation/TableDocumentation/{TableName}
```

This returns a JSON payload per table containing:

| Field | Description |
|---|---|
| `Fields[]` | Column name, type, and description (richer than public docs) |
| `ActionTypes[]` | **Full enumeration** — every valid ActionType value with description |
| `Queries[]` | Sample KQL queries provided by Microsoft |
| `HotDays` / `ColdDays` | Data retention periods |
| `TableType` | Table classification |
| `Tags[]` | Table tags/categories |

**Extractor script:** [`Get-DefenderSchema.ps1`](Get-DefenderSchema.ps1)

### 2. Microsoft Public Docs (Supplementary)

Raw markdown tables from [MicrosoftDocs/defender-docs](https://github.com/MicrosoftDocs/defender-docs) on GitHub. These provide the public column/type/description documentation but **do not include ActionTypes**.

**Sync script:** [`updater/sync-schema.ps1`](updater/sync-schema.ps1)

## Repository Structure

```
defender-xdr-advanced-hunting/
├── README.md
├── SKILL.md                              # Claude AI skill definition
├── Get-DefenderSchema.ps1                # Portal API schema extractor
├── parse-schema.js                       # Node.js parser: raw MD → JSON
│
├── schema/
│   ├── raw-md/                           # 61 raw markdown files from MS docs
│   │   └── advanced-hunting-{table}-table.md
│   └── parsed-json/                      # 61 parsed JSON schema files
│       └── {table}.json
│
└── updater/
    └── sync-schema.ps1                   # Pulls latest raw MD from GitHub
```

### Output Files (from `Get-DefenderSchema.ps1`)

```
DefenderSchema/
├── _AllTables.json                       # Combined schema — all tables in one file
├── DefenderXDR_SchemaReference.md        # Full human-readable reference
├── ActionTypes_Reference.md              # ActionTypes-only quick reference
└── {TableName}.json                      # Individual table JSON (×60)
```

## Schema Extraction

### Prerequisites

- Active session on [security.microsoft.com](https://security.microsoft.com) with Advanced Hunting access
- PowerShell 5.1+ (Windows PowerShell) or PowerShell 7+
- Browser DevTools to capture session cookies

### Authentication

The internal API uses session-based authentication through the portal's API proxy. It requires the **full browser cookie string** — not just `sccauth`. Key cookies include:

| Cookie | Purpose |
|---|---|
| `sccauth` | Primary session authentication |
| `XSRF-TOKEN` | CSRF protection (also sent as `x-xsrf-token` header) |
| `s.SessID` | Session routing |
| `X-PortalEndpoint-RouteKey` | Backend datacenter routing |
| `MUID`, `MS0`, `ai_session` | Telemetry/session correlation |

### Capturing Cookies

1. Open [security.microsoft.com](https://security.microsoft.com) and navigate to **Advanced Hunting**
2. Open DevTools (`F12`) → **Network** tab
3. In the portal, click any table name in the schema panel to trigger a `TableDocumentation` request
4. Click that request in the Network tab
5. Under **Request Headers**, find `Cookie:` and copy the **entire value**

> **Important:** Session cookies expire within 30–60 minutes. Copy them immediately before running the script.

### Running the Extractor

```powershell
.\Get-DefenderSchema.ps1 `
    -CookieString "<full-cookie-header-value>" `
    -TenantId "<your-entra-tenant-guid>"
```

#### Parameters

| Parameter | Required | Description |
|---|---|---|
| `-CookieString` | Yes | Full `Cookie:` header value from DevTools → Network |
| `-TenantId` | Yes | Your Entra ID (Azure AD) tenant GUID |
| `-OutputPath` | No | Output directory (default: `./DefenderSchema`) |
| `-Tables` | No | Array of specific table names; omit to pull all 60 tables |

#### Example — Pull Specific Tables

```powershell
.\Get-DefenderSchema.ps1 `
    -CookieString "sccauth=3Sq4kk...; XSRF-TOKEN=nd_kbWr..." `
    -TenantId "27c9901b-9650-4f50-b9b3-38611d797f9f" `
    -Tables @("DeviceProcessEvents", "DeviceEvents", "DeviceNetworkEvents")
```

### Updating Public Docs

To pull the latest raw markdown from Microsoft's GitHub:

```powershell
.\updater\sync-schema.ps1
```

Then parse into JSON:

```bash
node parse-schema.js
```

## Claude AI Skill

This repository is designed to be used as a [Claude custom skill](https://docs.claude.com). The `SKILL.md` file defines the behavior:

- Claude uses only documented schema fields — **no hallucinated column names or ActionType values**
- All queries are validated against the parsed JSON schema
- If a field doesn't exist in the schema, Claude says so explicitly
- KQL output is optimized for Advanced Hunting performance best practices

### Skill Rules

1. Never hallucinate fields
2. Only use documented schema fields
3. If a field is not documented, say so explicitly
4. Provide optimized KQL

## Tables Covered (61)

<details>
<summary>Click to expand full table list</summary>

| Table | Category |
|---|---|
| AADSignInEventsBeta | Identity |
| AADSpnSignInEventsBeta | Identity |
| AIAgentsInfo | AI/Copilot |
| AlertEvidence | Alerts |
| AlertInfo | Alerts |
| BehaviorEntities | Behavior |
| BehaviorInfo | Behavior |
| CampaignInfo | Threat Intelligence |
| CloudAppEvents | Cloud Apps |
| CloudAuditEvents | Cloud Apps |
| CloudProcessEvents | Cloud Apps |
| CloudStorageAggregatedEvents | Cloud Apps |
| DataSecurityBehaviors | Data Security |
| DataSecurityEvents | Data Security |
| DeviceBaselineComplianceAssessment | Device/TVM |
| DeviceBaselineComplianceAssessmentKB | Device/TVM |
| DeviceBaselineComplianceProfiles | Device/TVM |
| DeviceEvents | Device |
| DeviceFileCertificateInfo | Device |
| DeviceFileEvents | Device |
| DeviceImageLoadEvents | Device |
| DeviceInfo | Device |
| DeviceLogonEvents | Device |
| DeviceNetworkEvents | Device |
| DeviceNetworkInfo | Device |
| DeviceProcessEvents | Device |
| DeviceRegistryEvents | Device |
| DeviceTvmBrowserExtensions | Device/TVM |
| DeviceTvmBrowserExtensionsKB | Device/TVM |
| DeviceTvmCertificateInfo | Device/TVM |
| DeviceTvmHardwareFirmware | Device/TVM |
| DeviceTvmInfoGathering | Device/TVM |
| DeviceTvmInfoGatheringKB | Device/TVM |
| DeviceTvmSecureConfigurationAssessment | Device/TVM |
| DeviceTvmSecureConfigurationAssessmentKB | Device/TVM |
| DeviceTvmSoftwareEvidenceBeta | Device/TVM |
| DeviceTvmSoftwareInventory | Device/TVM |
| DeviceTvmSoftwareVulnerabilities | Device/TVM |
| DeviceTvmSoftwareVulnerabilitiesKB | Device/TVM |
| DisruptionAndResponseEvents | Incidents |
| EmailAttachmentInfo | Email |
| EmailEvents | Email |
| EmailPostDeliveryEvents | Email |
| EmailUrlInfo | Email |
| EntraIdSignInEvents | Identity |
| EntraIdSpnSignInEvents | Identity |
| ExposureGraphEdges | Exposure Management |
| ExposureGraphNodes | Exposure Management |
| FileMaliciousContentInfo | Data Security |
| GraphApiAuditEvents | Identity |
| IdentityAccountInfo | Identity |
| IdentityDirectoryEvents | Identity |
| IdentityEvents | Identity |
| IdentityInfo | Identity |
| IdentityLogonEvents | Identity |
| IdentityQueryEvents | Identity |
| MessageEvents | Teams/Comms |
| MessagePostDeliveryEvents | Teams/Comms |
| MessageUrlInfo | Teams/Comms |
| OAuthAppInfo | Cloud Apps |
| UrlClickEvents | Email |

</details>

## API Details

### Internal Endpoint

```
GET https://security.microsoft.com/apiproxy/mtp/huntingService/documentation/TableDocumentation/{TableName}
```

Backend (resolved by the API proxy):

```
https://m365d-hunting-api-prd-{region}.securitycenter.windows.com/api/ine/huntingservice/documentation/TableDocumentation/{TableName}
```

### Rate Limits

- **250 requests per minute** (header: `x-rate-limit-limit: 1m`)
- Remaining capacity returned in `x-rate-limit-remaining` header
- Script uses 300ms delay between requests (~200 req/min effective)

### Response Schema

```jsonc
{
  "Name": "DeviceProcessEvents",
  "Description": "Process creation and related events",
  "TableType": "Monitored",
  "HotDays": 30,
  "ColdDays": 150,
  "Tags": [],
  "Fields": [
    {
      "Name": "Timestamp",
      "Description": "Date and time when the event was recorded",
      "FieldType": "DateTime"
    }
    // ... additional fields
  ],
  "ActionTypes": [
    {
      "Name": "ProcessCreated",
      "Description": "A new process was created"
    },
    {
      "Name": "CreateRemoteThreadApiCall",
      "Description": "The CreateRemoteThread API was called"
    }
    // ... additional ActionTypes
  ],
  "Queries": [
    {
      "Name": "Sample query name",
      "Description": "What this query does",
      "QueryText": "DeviceProcessEvents | where ..."
    }
  ]
}
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| **HTTP 440** on every request | Cookies expired | Refresh the portal, re-copy the full cookie string, run immediately |
| **0 fields** returned (HTTP 200) | Missing `x-xsrf-token` header | Verify `XSRF-TOKEN` is present in your cookie string |
| **440 with fresh cookies** | Only `sccauth` + `XSRF-TOKEN` sent | Use the **full** cookie string from DevTools → Network, not individual cookies from Application → Cookies |
| `-AsUTC` parameter error | PowerShell 5.1 | Script handles this automatically; ensure you're running the latest version |

## License

This project extracts and reformats data from Microsoft Defender XDR for documentation and training purposes. Microsoft Defender XDR, Advanced Hunting, and all related table schemas are trademarks and intellectual property of Microsoft Corporation. Use of the extracted schema data is subject to your existing Microsoft licensing agreements.

## Contributing

1. Run `Get-DefenderSchema.ps1` against your tenant to generate fresh schema data
2. Compare against the existing `schema/parsed-json/` files for new tables or ActionTypes
3. Submit a PR with updated schema files and a summary of changes
