# Per-table recipes — Microsoft Sentinel

Sentinel speaks the same KQL as Defender Advanced Hunting but on a
different schema. Two universal differences:

  - **`TimeGenerated`** instead of `Timestamp` everywhere.
  - Tables come from connectors, not a fixed namespace — the available
    tables vary per workspace. The list below is the most common subset.

For Defender↔Sentinel field mapping (when porting a query from one to
the other) see `kql_translation.md`.

<!-- ============================================================== -->

## sentinel-table-SigninLogs

**Use cases**: Entra ID interactive sign-ins — geo, app, conditional access, MFA, risk.

**Columns that matter**:
- `TimeGenerated`, `UserPrincipalName`, `UserId`, `UserDisplayName`.
- `AppId`, `AppDisplayName`, `ResourceId`, `ResourceDisplayName`.
- `IPAddress`, `Location` (JSON), `LocationDetails`.
- `ResultType` — non-zero = failed sign-in. Common: `50053` (account locked), `50126` (bad password), `50140` (KMSI), `53003` (CA blocked).
- `ConditionalAccessStatus` — `Success`, `Failure`, `NotApplied`, `Unknown`.
- `RiskLevelDuringSignIn`, `RiskLevelAggregated`, `RiskState`, `RiskDetail`, `RiskEventTypes_V2`.
- `ClientAppUsed` — `Browser`, `Mobile Apps and Desktop clients`, `Other clients` (legacy auth).
- `IsInteractive`, `IsRisky`, `AuthenticationRequirement`, `MfaDetail` (JSON).
- `DeviceDetail` (JSON), `Status` (JSON).

**Common predicates**:
```kql
| where ResultType == 0                                    // success
| where ResultType != 0                                    // failure
| where ClientAppUsed == "Other clients"                   // legacy auth
| where ConditionalAccessStatus == "Failure"               // CA blocked
| where RiskLevelDuringSignIn in ("medium","high")
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
```

**Gotchas**:
- `Location` (string ISO code) and `LocationDetails` (JSON) are different. JSON has `city`, `state`, `countryOrRegion`, `geoCoordinates`.
- `ResultType` is INT not string — `== 0` not `== "0"`.
- Non-interactive sign-ins live in `AADNonInteractiveUserSignInLogs`, service principal in `AADServicePrincipalSignInLogs`. Union them when you want the full picture.

<!-- ============================================================== -->

## sentinel-table-AuditLogs

**Use cases**: Entra ID directory changes — group adds, role assignments, password resets, app consents, MFA changes.

**Columns that matter**:
- `TimeGenerated`, `OperationName`, `Category`, `Result`, `ResultReason`.
- `ActivityDateTime`, `ActivityDisplayName`.
- `LoggedByService` — `Core Directory`, `Authentication Methods`, `Application Proxy`, etc.
- `InitiatedBy` (JSON) — who did it (`user`, `app`, `provisioning`).
- `TargetResources` (JSON array) — what was acted on.
- `AdditionalDetails` (JSON).

**Common predicates**:
```kql
// Adds to privileged groups
| where OperationName has "Add member to role"
| extend RoleName = tostring(TargetResources[0].displayName),
         Member = tostring(TargetResources[1].displayName),
         Initiator = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| where RoleName has_any ("Global Administrator","Privileged Role Administrator",
                          "Application Administrator","User Access Administrator")
```

```kql
// New OAuth app consent grants — illicit-consent attack signal
| where OperationName =~ "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName),
         User = tostring(parse_json(InitiatedBy).user.userPrincipalName)
```

**Gotchas**:
- `TargetResources` is an array. Always `mv-expand` or index `[0]` / `[1]` carefully.
- `InitiatedBy` is JSON with two possible shapes: `user.*` or `app.*`. Cover both.

<!-- ============================================================== -->

## sentinel-table-SecurityEvent

**Use cases**: Windows Security event log (4624 logon, 4625 fail, 4688 process, 4720 user-create, 4768 Kerberos TGT, etc.). The default destination for Windows Security Auditing → Sentinel.

**Columns that matter**:
- `TimeGenerated`, `Computer`, `EventID`, `Activity`.
- `Account`, `AccountName`, `AccountDomain`, `AccountType`.
- `LogonType`, `LogonTypeName` — `Interactive` (2), `Network` (3), `Batch` (4), `Service` (5), `Unlock` (7), `RemoteInteractive` (10), `CachedInteractive` (11).
- `IpAddress`, `WorkstationName`, `LogonProcessName`, `AuthenticationPackageName`.
- `FailureReason`, `Status`, `SubStatus` — populated on `EventID == 4625`.
- `ProcessName`, `NewProcessName`, `CommandLine`, `ParentProcessName`, `NewProcessId`, `ProcessId`, `TokenElevationType` — populated on `EventID == 4688` (process-create).
- `TargetUserName`, `TargetDomainName`, `TargetUserSid` — for actions affecting another account.
- `SubjectUserName`, `SubjectDomainName`, `SubjectUserSid`, `SubjectLogonId` — for the actor.
- `EventData` — raw XML payload for fields not promoted to columns.

**Common predicates**:
```kql
// Failed interactive logons
| where EventID == 4625 and LogonType in (2, 10)
| where AccountType == "User"
| where Account !endswith "$"

// New process via 4688 (must have audit policy enabled)
| where EventID == 4688
| where AccountType == "User"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine,
          ParentProcessName, TokenElevationType
```

**Gotchas**:
- 4688 `CommandLine` is **not collected by default** — requires the GPO "Include command line in process creation events" enabled.
- `Account` is `domain\user` format; `AccountName` is just the user portion.
- This table can be very high volume. Pre-filter `EventID` first.

<!-- ============================================================== -->

## sentinel-table-WindowsEvent

**Use cases**: newer Windows event collector format — covers Application, System, Security and custom Sysmon channels.

**Columns that matter**:
- `TimeGenerated`, `Computer`, `EventID`, `Channel`, `Provider`, `Description`.
- `EventData` (dynamic) — provider-specific payload; access via `EventData.<Field>`.
- `Level`, `EventLevelName`, `Task`, `Keywords`.

**Common predicates**:
```kql
// Sysmon EID 1 process create
WindowsEvent
| where TimeGenerated > ago(7d)
| where Provider == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend Image = tostring(EventData.Image),
         CommandLine = tostring(EventData.CommandLine),
         Parent = tostring(EventData.ParentImage),
         User = tostring(EventData.User)
```

**Gotchas**:
- `EventData` is dynamic — every Provider has a different shape. Read MS Sysmon docs for the field list.
- This table sometimes co-exists with `Event` (legacy collector) — when migrating, alias both.

<!-- ============================================================== -->

## sentinel-table-Syslog

**Use cases**: Linux endpoint logs (syslog, rsyslog, journald via mma/ama).

**Columns that matter**:
- `TimeGenerated`, `Computer`, `HostName`, `HostIP`.
- `Facility`, `FacilityName` — `auth`, `authpriv`, `daemon`, etc.
- `SeverityLevel`, `ProcessName`, `ProcessID`, `SyslogMessage`.

**Common predicates**:
```kql
// Failed sudo attempts
| where Facility =~ "authpriv"
| where SyslogMessage has "sudo:" and SyslogMessage has "FAILED"
| project TimeGenerated, Computer, HostIP, SyslogMessage

// SSH key-based logon
| where ProcessName =~ "sshd"
| where SyslogMessage has "Accepted publickey"
| extend SrcIp = extract(@"from\s+(\S+)", 1, SyslogMessage),
         User  = extract(@"for\s+(\S+)\s+from", 1, SyslogMessage)
```

**Gotchas**:
- `SyslogMessage` is unstructured — bring your own regex.
- For rich Linux process telemetry, prefer ASIM `ImProcessCreate` or `auoms`-driven custom tables.

<!-- ============================================================== -->

## sentinel-table-OfficeActivity

**Use cases**: O365 audit — Exchange, SharePoint, OneDrive, Teams, AAD admin.

**Columns that matter**:
- `TimeGenerated`, `OfficeWorkload` — `Exchange`, `SharePoint`, `OneDrive`, `MicrosoftTeams`, `AzureActiveDirectory`.
- `Operation` — workload-specific. e.g. `MailboxLogin`, `Send`, `New-InboxRule`, `FileUploaded`, `MemberAdded`, `MessageSent`.
- `RecordType`, `ResultStatus`.
- `UserId`, `UserKey`, `UserType`, `ClientIP`, `UserAgent`.
- `Subject`, `Sender`, `Recipients` — Exchange-only.
- `Site_Url`, `ObjectId`, `SourceFileName`, `DestinationFileName` — SharePoint/OneDrive.
- `MailboxOwnerUPN`, `ItemSize`, `MessageId`, `InternetMessageId`, `Verdict`, `DeliveryAction`.

**Common predicates**:
```kql
// New inbox rules created — common BEC artefact
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule","Set-InboxRule")
| where ResultStatus == "Succeeded"
| project TimeGenerated, UserId, ClientIP, Operation, Parameters

// Mass file download from SharePoint / OneDrive
| where OfficeWorkload in ("SharePoint","OneDrive")
| where Operation =~ "FileDownloaded"
| summarize Files = dcount(SourceFileName), Sites = make_set(Site_Url)
            by UserId, bin(TimeGenerated, 5m)
| where Files > 100
```

**Gotchas**:
- `Parameters` is a JSON-stringified array on Exchange — `parse_json(Parameters)` to access individual params.
- High volume. Always pre-filter by `OfficeWorkload` and `Operation`.

<!-- ============================================================== -->

## sentinel-table-AzureActivity

**Use cases**: Azure Resource Manager control-plane events — VM start/stop, RBAC changes, storage container creation, key vault reads.

**Columns that matter**:
- `TimeGenerated`, `OperationNameValue`, `Category`, `CategoryValue`, `ResourceId`.
- `Caller` — UPN or service principal that initiated.
- `CallerIpAddress` — source IP (note: often null for service principals).
- `ResourceProviderValue`, `ResourceGroup`, `SubscriptionId`.
- `ActivityStatus`, `ActivityStatusValue` — `Started`, `Accepted`, `Succeeded`, `Failed`.
- `Properties` (JSON) — operation-specific payload.

**Common predicates**:
```kql
// Role assignments outside known IT
| where OperationNameValue =~ "Microsoft.Authorization/roleAssignments/write"
| where ActivityStatusValue == "Succeeded"
| extend Role = tostring(parse_json(Properties).requestbody)
| project TimeGenerated, Caller, CallerIpAddress, ResourceId, Role

// Key Vault secret reads from outside the tenant
| where OperationNameValue =~ "Microsoft.KeyVault/vaults/secrets/read"
| where ActivityStatusValue == "Succeeded"
```

**Gotchas**:
- Subscription-scoped. Make sure your data connector covers all subs of interest.
- `Caller` may be a GUID for service principals — join with `IdentityInfo` to enrich.

<!-- ============================================================== -->

## sentinel-table-CommonSecurityLog

**Use cases**: Common Event Format (CEF) feed — Palo Alto, Cisco ASA, Check Point, F5, Fortinet, Sophos, Imperva, ZScaler.

**Columns that matter**:
- `TimeGenerated`, `DeviceVendor`, `DeviceProduct`, `DeviceVersion`.
- `DeviceEventClassID`, `Activity`, `LogSeverity`, `Message`.
- `SourceIP`, `SourcePort`, `SourceUserName`, `SourceHostName`.
- `DestinationIP`, `DestinationPort`, `DestinationUserName`, `DestinationHostName`.
- `RequestURL`, `RequestMethod`, `RequestClientApplication` (User-Agent).
- `ApplicationProtocol`, `Protocol`, `EventOutcome`, `DeviceAction`.
- `SentBytes`, `ReceivedBytes`.
- `FileName`, `FileHash`, `FileSize`, `FilePath`.
- `DeviceCustomString*`, `DeviceCustomNumber*`, `FlexString*`, `FlexNumber*` — vendor-specific extensions.

**Common predicates**:
```kql
// Firewall denies from public IPs
| where DeviceVendor =~ "Palo Alto Networks"
| where Activity has "deny" or DeviceAction has "deny"
| where ipv4_is_private(SourceIP) == false

// Web proxy threat hits
| where DeviceVendor =~ "Zscaler"
| where DeviceCustomString1 has_any ("malware","phishing","botnet","spyware")
```

**Gotchas**:
- Vendor-specific semantics — always pin `DeviceVendor` + `DeviceProduct` first; Activity values aren't standardized across vendors.
- `DeviceCustomString*` mappings are documented per vendor, NOT in MS docs.

<!-- ============================================================== -->

## sentinel-table-ThreatIntelligenceIndicator

**Use cases**: TI feed indicators (IPs, hashes, domains, URLs, emails).

**Columns that matter**:
- `TimeGenerated`, `IndicatorId`, `Action`, `Active`, `IsActive`, `ExpirationDateTime`.
- `Description`, `ConfidenceScore`, `ThreatType`, `Tags`.
- `NetworkIP`, `NetworkSourceIP`, `NetworkDestinationIP`, `NetworkPort`, `Url`, `DomainName`.
- `FileHashType`, `FileHashValue`, `FileName`.
- `EmailSenderAddress`, `EmailSubject`.

**Common pattern — sweep network telemetry against active TI**:
```kql
let Active = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where ExpirationDateTime > now()
    | summarize arg_max(TimeGenerated, *) by IndicatorId
    | where isnotempty(NetworkIP);
CommonSecurityLog
| where TimeGenerated > ago(7d)
| join kind=inner (Active | project NetworkIP, ThreatType, ConfidenceScore)
    on $left.DestinationIP == $right.NetworkIP
```

**Gotchas**:
- An indicator can have many time-snapshots — `arg_max(TimeGenerated, *)` gets the latest.
- `IsActive` and `Active` are both boolean fields; some connectors use one, some the other.

<!-- ============================================================== -->

## sentinel-table-SecurityAlert

**Use cases**: Aggregated alert stream (Defender for Cloud, Defender for Identity, third-party connectors).

**Columns that matter**:
- `TimeGenerated`, `AlertName`, `AlertSeverity`, `Description`.
- `ProviderName`, `VendorName`, `VendorOriginalId`, `SystemAlertId`.
- `ResourceId`, `SourceComputerId`.
- `IsIncident`, `Status`, `CompromisedEntity`.
- `Tactics`, `Techniques` (string arrays).
- `Entities` (JSON) — actors involved.
- `ExtendedProperties` (JSON) — alert-specific metadata.

**Common predicates**:
```kql
| where AlertSeverity in ("High","Medium")
| where ProviderName =~ "MDATP"
| extend Hosts = parse_json(Entities)
| mv-expand Hosts
| where Hosts.Type == "host"
| extend Hostname = tostring(Hosts.HostName)
```

<!-- ============================================================== -->

## sentinel-table-SecurityIncident

**Use cases**: Sentinel-side incident container (correlates multiple alerts).

**Columns that matter**:
- `TimeGenerated`, `IncidentName`, `IncidentNumber`, `Title`, `Description`.
- `Severity`, `Status` — `New`, `Active`, `Closed`.
- `Classification`, `ClassificationReason`, `ClassificationComment`.
- `Owner`, `Labels`, `Comments`.
- `FirstActivityTime`, `LastActivityTime`.
- `AlertIds` (array), `BookmarkIds` (array), `RelatedAnalyticRuleIds` (array).
- `Tactics`, `Techniques`.

<!-- ============================================================== -->

## sentinel-table-DnsEvents

**Use cases**: Windows DNS server logs.

**Columns that matter**:
- `TimeGenerated`, `Computer`, `ClientIP`, `Name` (queried domain).
- `QueryType`, `QueryTypeName`, `ResultCode`, `ResultCodeName`.
- `Question`, `Result`.

**Common predicates**:
```kql
| where Name endswith ".onion" or Name endswith ".duckdns.org"
| project TimeGenerated, Computer, ClientIP, Name, QueryType, ResultCodeName

// DNS-tunnel candidate — high-volume TXT queries
| where QueryTypeName == "TXT"
| summarize Queries = count(), Names = dcount(Name) by ClientIP, bin(TimeGenerated, 5m)
| where Queries > 200
```

<!-- ============================================================== -->

## sentinel-table-W3CIISLog

**Use cases**: IIS access logs.

**Columns that matter**:
- `TimeGenerated`, `Computer`, `sSiteName`, `csMethod`, `csUriStem`, `csUriQuery`.
- `cIP`, `csUserAgent`, `csUserName`, `csReferer`.
- `scStatus`, `scSubStatus`, `scWin32Status`, `TimeTaken`, `csBytes`, `scBytes`.

**Common predicates**:
```kql
// Web-shell file access (cmd-prompted via aspx)
| where csUriStem matches regex @"(?i)\.(aspx?|cfm|jsp|asp)$"
| where csUriQuery has_any ("cmd=","exec=","whoami","powershell")

// Successful sign-in to admin URI from public IP
| where csUriStem has "/admin"
| where scStatus == 200
| where ipv4_is_private(cIP) == false
```

<!-- ============================================================== -->

## sentinel-table-ASIM-overview

**Use cases**: Microsoft's CIM-equivalent — a normalised view that abstracts over multiple connectors.

ASIM tables (`Im*` prefix) provide a unified schema across vendors — query `ImProcessCreate` and you'll get rows from MDE, Sysmon, AuditD, CrowdStrike, etc., all with the same column names. Pay-the-cost-once for portable detections.

**Common ASIM tables**:
| Table                | Defender XDR analogue        | Use cases                             |
|----------------------|------------------------------|---------------------------------------|
| `ImProcessCreate`    | `DeviceProcessEvents`        | Cross-vendor process-create detection |
| `ImProcessTerminate` | (none)                       | Process exits                         |
| `ImNetworkSession`   | `DeviceNetworkEvents`        | Cross-vendor network sessions         |
| `ImAuthentication`   | `IdentityLogonEvents` + AAD  | Auth across cloud + on-prem           |
| `ImWebSession`       | `DeviceNetworkEvents` (HTTP) | Web proxy + endpoint web              |
| `ImFileEvent`        | `DeviceFileEvents`           | File create/modify across vendors     |
| `ImDnsActivity`      | `DeviceEvents` (DnsQuery)    | Cross-vendor DNS                      |
| `ImRegistryEvent`    | `DeviceRegistryEvents`       | Registry across vendors               |

**Common shape — process create**:
```kql
ImProcessCreate
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where TargetProcessName =~ "powershell.exe"
| where ParentProcessName in~ ("winword.exe","excel.exe","outlook.exe")
| project TimeGenerated, DvcHostname, ActorUsername,
          TargetProcessCommandLine, ParentProcessName
```

> **Detection-engineering tip**: when authoring a cross-vendor detection,
> write it once against ASIM (`Im*`) and let the connector normalisation
> handle vendor-specific ingestion. When latency or a vendor-specific
> field matters, fall back to the raw connector table.

<!-- ============================================================== -->

## sentinel-watchlists

Sentinel watchlists are scoped lookup tables (CSV-driven) accessible
from any KQL query. Define once, reuse everywhere — they replace the
recurring `let allowlist = dynamic([...])` pattern at scale.

**Pattern — exclude an allowlist**:
```kql
let _allowed_admins = _GetWatchlist("KnownAdmins")
    | project AccountUpn = SearchKey;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| where ResourceDisplayName == "Microsoft Graph"
| where AccountUpn !in (_allowed_admins)
```

**Gotchas**:
- `_GetWatchlist("Name")` requires the watchlist to have a `SearchKey` column declared at creation time.
- Watchlists are typed `string`; numeric comparisons need explicit `toint()`/`tolong()` casts.
- Updates take a few minutes to propagate — don't use them as time-critical IOC feeds.
