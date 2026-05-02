# Per-table recipes — Defender Advanced Hunting

For each table: the columns that actually matter for detection
engineering, common predicates, common joins, gotchas. Drawn from the
BluRaven course + the Defender schema reference (tables are populated
in `data_sources/defender_spec_tables.json`).

<!-- ============================================================== -->

## table-DeviceProcessEvents

**Use cases**: process execution, parent/child relationships, command-
line analysis, hash/path-of-binary forensics.

**Columns that matter**:
- `Timestamp` — every detection needs a time predicate.
- `DeviceName`, `DeviceId` — host identity. `DeviceId` is stable; name can change.
- `AccountName`, `AccountDomain` — initiating user. `AccountSid` is the cleanest pivot.
- `FileName`, `FolderPath`, `SHA256`, `SHA1`, `MD5` — child binary.
- `ProcessCommandLine` — the actual invocation. Lower-cased version available via `ProcessCommandLine` (Defender doesn't normalise — `tolower()` it before matching).
- `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `InitiatingProcessFolderPath`, `InitiatingProcessSHA256` — parent.
- `InitiatingProcessParentFileName` — grandparent (rare but useful for chains).
- `InitiatingProcessIntegrityLevel` — `System`/`High`/`Medium` — privileged-vs-user heuristic.
- `IsInitiatingProcessRemoteSession` — RDP/WinRM-spawned process.

**Common predicates**:
```kql
| where InitiatingProcessFileName =~ "outlook.exe"   // case-insensitive eq
| where FileName has_any (...)                       // multi-value match, indexed
| where ProcessCommandLine has "powershell"          // substring, indexed
| where AccountName !has "$"                         // skip machine accounts
```

**Joins**:
```kql
// Process spawned by a network connection on the same machine
DeviceProcessEvents
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | project NetworkTime = Timestamp, DeviceId, RemoteIP
  ) on DeviceId
| where Timestamp between (NetworkTime .. NetworkTime + 60s)
```

**Gotchas**:
- `=~` is case-insensitive equality; `==` is exact.
- `has` matches token-aligned substrings (faster); `contains` is fragment match (slower, sometimes catches what `has` misses).
- ETW signal is sometimes ~30-60s behind realtime — use `bin(Timestamp, 5m)` for charts.

<!-- ============================================================== -->

## table-DeviceNetworkEvents

**Use cases**: outbound connections, beaconing, C2 detection, LOLBin egress.

**Columns that matter**:
- `Timestamp`, `DeviceName`, `DeviceId`.
- `ActionType` — `ConnectionSuccess`, `ConnectionFailed`, `ConnectionAttempt`, `ListeningConnectionCreated`, `InboundConnectionAccepted`, `DnsQueryResponse`, `HttpConnectionInspected`.
- `RemoteIP`, `RemotePort`, `RemoteUrl` — destination triple.
- `RemoteIPType` — `Public`, `Private`, `Loopback`, etc. Filter `=="Public"` to skip lateral.
- `Protocol` — `Tcp`, `Udp`, `Icmp`.
- `LocalIP`, `LocalPort` — useful for listener detections.
- `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `InitiatingProcessSHA256` — process that opened the socket.

**Beaconing pattern**:
```kql
DeviceNetworkEvents
| where Timestamp > ago(2h)
| where RemoteIPType == "Public"
| summarize ConnCount = count(),
            DistinctMinutes = dcount(bin(Timestamp, 1m))
            by DeviceId, RemoteIP, RemotePort, InitiatingProcessFileName
| where ConnCount > 50 and DistinctMinutes > 30   // sustained, not bursty
```

**Gotchas**:
- DNS resolution is in `DeviceEvents` (`ActionType == "DnsQueryResponse"`) — `RemoteUrl` here is what the host resolved to, not the original CNAME chain.
- `RemoteUrl` can be empty when only an IP was contacted — fall back to `RemoteIP`.
- Some agent versions emit `ConnectionAttempt` only; others emit `ConnectionSuccess`. Filter both.

<!-- ============================================================== -->

## table-EmailEvents

**Use cases**: phishing detection, BEC, mail-based malware delivery.

**Columns that matter**:
- `Timestamp` — when the message was processed.
- `NetworkMessageId` — unique per message; the join key for `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`.
- `SenderFromAddress` (header from), `SenderMailFromAddress` (envelope), `SenderObjectId` (AAD object id when internal).
- `RecipientEmailAddress`, `RecipientObjectId`.
- `Subject`, `SubjectLanguage`, `SenderDisplayName`.
- `DeliveryAction` — `Delivered`, `Junked`, `Blocked`, `Replaced`, `DeliveredAsSpam`.
- `DeliveryLocation` — `Inbox`, `JunkFolder`, `Quarantine`, `External`, etc.
- `EmailDirection` — `Inbound`, `Outbound`, `Intra-org`. Always filter inbound for phishing.
- `AuthenticationDetails` — SPF/DKIM/DMARC results.

**Phishing-with-link join**:
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| join kind=inner (
    EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
  ) on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | project NetworkMessageId, ClickTimestamp = Timestamp, AccountUpn
  ) on NetworkMessageId
| project Timestamp, ClickTimestamp, SenderFromAddress, RecipientEmailAddress,
          Subject, Url, UrlDomain, AccountUpn
```

**Gotchas**:
- One message can have multiple URLs / attachments — `NetworkMessageId` is many-to-many.
- `SenderFromAddress` is what the recipient sees; it can be spoofed. Use `SenderMailFromAddress` for SPF/DMARC anchoring.
- Reply-thread chains share thread metadata but each message has its own `NetworkMessageId`.

<!-- ============================================================== -->

## table-IdentityLogonEvents

**Use cases**: Windows auth (Kerberos/NTLM), interactive logon, lateral movement, golden ticket.

**Columns that matter**:
- `Timestamp`, `DeviceName`, `AccountUpn`, `AccountSid`.
- `LogonType` — `Interactive`, `RemoteInteractive`, `Network`, `Service`, `NetworkCleartext`, `Batch`, `Unlock`, `CachedInteractive`.
- `Protocol` — `Kerberos`, `NTLM`, `Other`. NTLM where Kerberos is expected = pivot signal.
- `ActionType` — `LogonSuccess`, `LogonFailed`.
- `IPAddress`, `Port`, `Workstation`.
- `LogonId` — session id for joins to other identity tables.
- `FailureReason` — for `LogonFailed`.

**Common predicates**:
```kql
| where LogonType == "RemoteInteractive" and Protocol == "NTLM"   // RDP via NTLM = unusual
| where AccountUpn endswith "@yourdomain.com"
| where ActionType == "LogonFailed" and FailureReason has "BadPassword"
```

**Gotchas**:
- Service accounts often log on as `Service`/`Batch` — exclude unless that's the detection.
- A single user can produce 30+ events per minute on a busy host — bin/dedupe.

<!-- ============================================================== -->

## table-AADSignInEventsBeta

**Use cases**: Entra ID (Azure AD) sign-ins, MFA bypass, conditional access.

**Columns that matter**:
- `Timestamp`, `AccountObjectId`, `AccountUpn`, `AccountDisplayName`.
- `IPAddress`, `Country`, `City`, `State`.
- `ApplicationId`, `Application`, `AppDisplayName` — which AAD app the sign-in was for.
- `ResourceId`, `ResourceTenantId` — service principal target.
- `ConditionalAccessStatus` — `Success`, `Failure`, `NotApplied`, `Unknown`.
- `ErrorCode` — non-zero is a failed sign-in. Specific codes: `50053` (locked), `50126` (bad password), `50140` (KMSI prompt), `53003` (CA blocked), `530032` (security default blocked).
- `ClientAppUsed` — `Browser`, `Mobile Apps and Desktop clients`, `Other clients` (legacy auth).
- `IsAnonymousProxy`, `RiskLevelDuringSignIn`, `RiskState`, `RiskDetail`.
- `MfaDetail` — JSON with auth methods used.

**Common patterns**:
```kql
// Legacy auth still in use
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ClientAppUsed == "Other clients"
| where ErrorCode == 0
| summarize Sessions = count() by AccountUpn, IPAddress, Application
```

**Gotchas**:
- "Beta" suffix — schema can change without notice. Read MSFT changelogs.
- `Country` is geo-IP; corporate VPNs and Tor mess with it.
- Risky sign-ins surface in `RiskState`/`RiskDetail` only after Identity Protection scoring — there's a delay.

<!-- ============================================================== -->

## table-DeviceFileEvents

**Use cases**: file creation, modification, drop sites, shadow-copy deletion.

**Columns that matter**:
- `Timestamp`, `DeviceName`, `ActionType` (`FileCreated`, `FileModified`, `FileDeleted`, `FileRenamed`).
- `FileName`, `FolderPath`, `SHA256`, `MD5`, `SHA1`.
- `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `InitiatingProcessAccountName`.

**Common predicates**:
```kql
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\", @"\Public\")
| where FileName endswith ".dll" or FileName endswith ".bat"
```

**Gotchas**:
- `FileDeleted` events are emitted after the deletion completes — short retention.
- Volume Shadow Copy deletion (`vssadmin delete shadows`) shows up here when the snapshot files vanish.

<!-- ============================================================== -->

## table-DeviceRegistryEvents

**Use cases**: persistence, autorun, service hijacks, defence evasion.

**Columns that matter**:
- `Timestamp`, `DeviceName`, `ActionType` (`RegistryKeyCreated`, `RegistryValueSet`, `RegistryKeyDeleted`).
- `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `RegistryValueType`.
- `InitiatingProcessFileName`, `InitiatingProcessAccountName`.

**Persistence locations to watch**:
- `\Run`, `\RunOnce` (HKCU + HKLM)
- `\Image File Execution Options\` (debugger hijack)
- `\Services\` (service installation)
- `\Microsoft\Windows\CurrentVersion\Winlogon\Userinit`
- `\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\Run", @"\RunOnce", @"\Image File Execution Options")
| where InitiatingProcessFileName !in~ ("msiexec.exe","explorer.exe")  // legit installers
```

<!-- ============================================================== -->

## table-DeviceEvents

**Use cases**: catch-all for everything that isn't one of the above (DNS responses, AMSI scans, Defender alerts, BitLocker events, USB).

**Columns that matter**:
- `ActionType` — the discriminator. Hundreds of values; consult MS docs.
- `Timestamp`, `DeviceName`, `InitiatingProcess*`.
- `AdditionalFields` — variant JSON; use `parse_json` then `.field`.

**DNS query example**:
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend Q = tostring(parse_json(AdditionalFields).QueryName)
| where Q endswith ".onion" or Q endswith ".ru"
| project Timestamp, DeviceName, Q, InitiatingProcessFileName
```

**Gotchas**:
- The `AdditionalFields` JSON shape changes per `ActionType`. There's no single schema.
- This table is huge — always filter by `ActionType` first.

<!-- ============================================================== -->

## table-DeviceLogonEvents

**Use cases**: Windows interactive/network logons at the host level (mirror of `IdentityLogonEvents` but client-side, with extra context like `IsLocalAdmin` and `LogonId`).

**Columns that matter**:
- `Timestamp`, `DeviceName`, `DeviceId`.
- `AccountName`, `AccountDomain`, `AccountSid` — the user logging on.
- `LogonType` — `Interactive`, `RemoteInteractive` (RDP), `Network`, `Service`, `Batch`, `NetworkCleartext`, `Unlock`, `CachedInteractive`.
- `ActionType` — `LogonSuccess`, `LogonFailed`, `LogonAttempted`.
- `Protocol` — `Kerberos`, `NTLM`, etc.
- `FailureReason` — populated when `ActionType == "LogonFailed"`.
- `RemoteIP`, `RemoteIPType`, `RemoteDeviceName`, `RemotePort` — origin of the auth.
- `IsLocalAdmin` — bool. Useful pivot for privilege detection.
- `LogonId`, `ReportId` — joins back to other identity / process tables.
- `InitiatingProcess*` — the process that triggered the logon (rare but useful).

**Common predicates**:
```kql
| where ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"   // RDP
| where ActionType == "LogonFailed"  and FailureReason has "BadPassword"     // brute-force
| where Protocol == "NTLM" and LogonType == "RemoteInteractive"              // NTLM-over-RDP smell
| where IsLocalAdmin == true and LogonType in ("Interactive","Network")      // privilege use
```

**Gotchas**:
- High-volume — service accounts log on repeatedly. Always exclude with `AccountName !endswith "$"` and / or `LogonType !in ("Service","Batch")`.
- `RemoteDeviceName` is sometimes empty for cloud-AAD logons; use `RemoteIP` as fallback.

<!-- ============================================================== -->

## table-DeviceImageLoadEvents

**Use cases**: DLL / module loads — DLL hijack, side-loading, unsigned-DLL hunting, AMSI bypass detection.

**Columns that matter**:
- `Timestamp`, `DeviceName`, `DeviceId`, `ActionType` (always `ImageLoaded`).
- `FileName`, `FolderPath`, `SHA1`, `SHA256`, `MD5`, `FileSize` — the loaded DLL.
- `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessSHA256`, `InitiatingProcessCommandLine`, `InitiatingProcessAccountName` — the process that loaded it.

**Common predicates**:
```kql
// Side-loaded DLL adjacent to an unsigned binary
| where InitiatingProcessFolderPath has @"\AppData\Local\Temp\"
| where FolderPath =~ InitiatingProcessFolderPath
   and SHA256 != InitiatingProcessSHA256

// Suspicious DLL loaded by lsass.exe (credential theft tooling)
| where InitiatingProcessFileName =~ "lsass.exe"
| where FolderPath !startswith @"C:\Windows\"
```

**Gotchas**:
- Extremely high volume — 1000+ loads per minute per host is normal. Always pre-filter by parent process or path.
- `InitiatingProcessSHA256` is the loader; `SHA256` is the loaded module. Don't confuse them.

<!-- ============================================================== -->

## table-DeviceInfo

**Use cases**: device inventory snapshot — used as a join source to filter by OS, group, or join-state. Daily heartbeat row.

**Columns that matter**:
- `DeviceId`, `DeviceName`, `Timestamp`.
- `OSPlatform` — `Windows10`, `Windows11`, `WindowsServer2019`, `Linux`, `MacOS`, etc.
- `OSVersion`, `OSBuild`, `OSArchitecture`, `OSDistribution`.
- `Model`, `Vendor`, `DeviceCategory`, `DeviceType`, `DeviceSubtype`.
- `MachineGroup` — Defender-side tagging.
- `JoinType` — `AzureAD`, `Hybrid`, `Workgroup`.
- `IsAzureADJoined`, `IsInternetFacing` — bool pivots.
- `LoggedOnUsers` — JSON array of currently signed-in users.
- `PublicIP`, `AadDeviceId`.

**Common pattern — dynamic device-set filter**:
```kql
let win10 = DeviceInfo
    | where OSPlatform == "Windows10"
    | summarize make_set(DeviceName);
DeviceProcessEvents
| where DeviceName in (win10)
| where FileName =~ "sethc.exe"
```

**Gotchas**:
- One row per device per day — don't `count()` events here, that's not what it represents.
- `LoggedOnUsers` is JSON; use `parse_json(LoggedOnUsers)` then `mv-expand`.

<!-- ============================================================== -->

## table-DeviceNetworkInfo

**Use cases**: network-adapter inventory — mainly for joining VPN/IP context to other tables.

**Columns that matter**:
- `DeviceId`, `DeviceName`, `Timestamp`.
- `NetworkAdapterName`, `NetworkAdapterType`, `NetworkAdapterStatus`.
- `MacAddress`, `IPAddresses` (dynamic), `IPv4Dhcp`, `IPv6Dhcp`.
- `DnsAddresses`, `DefaultGateways`.
- `ConnectedNetworks`, `TunnelType`.

**Gotchas**:
- Daily-ish snapshot, not real-time — don't expect to see every IP change.
- `IPAddresses` is a dynamic array; `mv-expand` to flatten.

<!-- ============================================================== -->

## table-EmailUrlInfo

**Use cases**: every URL inside every inbound/outbound message — the join partner for `EmailEvents` when you want URL details.

**Columns that matter**:
- `Timestamp`, `NetworkMessageId` — the join key into `EmailEvents` and `UrlClickEvents`.
- `Url`, `UrlDomain` — the destination.
- `UrlLocation` — `Body`, `Subject`, `Header`, `Attachment` — where it was found.
- `ReportId`.

**Common join (the canonical phishing pattern)**:
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| join kind=inner (
    EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
  ) on NetworkMessageId
```

**Gotchas**:
- One message can have many URLs — `NetworkMessageId` is many-to-many.
- `UrlDomain` is pre-extracted by Defender; trust it, don't re-parse from `Url`.

<!-- ============================================================== -->

## table-EmailAttachmentInfo

**Use cases**: attachment metadata + Defender's malware verdict on each attachment.

**Columns that matter**:
- `Timestamp`, `NetworkMessageId` — join into `EmailEvents`.
- `SenderFromAddress`, `RecipientEmailAddress`.
- `FileName`, `FileType`, `FileSize`, `SHA256`.
- `MalwareFilterVerdict` — `Malware`, `Phish`, `Spam`, `None`, etc.
- `MalwareDetectionMethod`, `ThreatTypes`, `ThreatNames`, `DetectionMethods`.

**Common predicates**:
```kql
// Malicious attachments delivered to mailbox
| where MalwareFilterVerdict == "Malware"
| where FileType in~ ("DOC","DOCX","XLS","XLSM","ISO","IMG","ZIP","RAR","HTML")
```

**Gotchas**:
- `SHA256` here is the attachment hash — pivot to `DeviceFileEvents` to see if it actually wrote to disk.

<!-- ============================================================== -->

## table-EmailPostDeliveryEvents

**Use cases**: post-delivery actions — ZAP (Zero-hour Auto Purge), manual move-to-junk, soft-delete by user.

**Columns that matter**:
- `Timestamp`, `NetworkMessageId`, `InternetMessageId`.
- `Action` — what happened (`Delete`, `MoveToJunk`, etc.).
- `ActionType` — `Manual`, `ZAP`, `Auto`.
- `ActionTrigger` — what initiated the action (`User`, `System`, `Admin`).
- `ActionResult` — success/fail.
- `DeliveryLocation`, `RecipientEmailAddress`.

**Gotchas**:
- Post-delivery isn't the same as deletion — the message may still be in another folder; only `Delete` actions remove it.

<!-- ============================================================== -->

## table-UrlClickEvents

**Use cases**: Safe-Links click telemetry — when a user actually opened a URL from email/Teams. The signal that turns "phish was delivered" into "phish was clicked".

**Columns that matter**:
- `Timestamp`, `Url`, `AccountUpn` — who clicked, when.
- `ActionType` — `ClickAllowed`, `ClickedThrough`, `ClickBlocked`, `Blocked`.
  - `ClickAllowed` = Safe Links allowed it; user reached the URL.
  - `ClickedThrough` = user bypassed a Safe-Links warning.
- `NetworkMessageId` — joins back to `EmailEvents` to get the message context.
- `Workload` — `Email`, `Teams`, `Office`.
- `ThreatTypes`, `DetectionMethods`.
- `IsClickedThrough` (bool).
- `IPAddress`, `UrlChain` (redirect chain), `ReportId`, `Application`.

**Common pattern — full phishing-to-process correlation**:
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| join kind=inner (EmailUrlInfo | project NetworkMessageId, Url) on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | project NetworkMessageId, ClickTime = Timestamp, AccountUpn
  ) on NetworkMessageId
```

**Gotchas**:
- Click data only exists for tenants with Safe Links (Defender for O365 P1+).
- `ClickedThrough == true` is a high-fidelity user-bypass signal — pair with subsequent process spawn.

<!-- ============================================================== -->

## table-IdentityQueryEvents

**Use cases**: LDAP/SAMR query telemetry — recon detection (BloodHound, ADRecon, kerberoasting prelude).

**Columns that matter**:
- `Timestamp`, `ActionType` — `LDAPQuery`, `SAMRQuery`, `DNSQuery`, etc.
- `Query` — the actual LDAP filter string.
- `QueryTarget` — what's being queried.
- `QueryType`, `Protocol`.
- `AccountName`, `AccountDomain`, `AccountUpn`.
- `DeviceName`, `IPAddress` — origin host.

**Common predicates**:
```kql
// BloodHound-style enumeration of all users
| where ActionType == "LDAPQuery"
| where Query has "(samAccountType=805306368)"           // user objects

// Kerberoasting recon — querying SPNs
| where Query has "servicePrincipalName"
```

**Gotchas**:
- High-volume on DCs; bin and aggregate by `AccountName` to find outliers.
- LDAP queries are OFTEN benign — pair with rare-source-host or unusual-time signal.

<!-- ============================================================== -->

## table-IdentityDirectoryEvents

**Use cases**: Active Directory / Entra ID directory changes — group membership, password resets, account creation, MFA changes.

**Columns that matter**:
- `Timestamp`, `ActionType` — long enum: `Group Membership changed`, `Password change attempt`, `User Account modified`, `Forced password reset`, `Account created`, etc.
- `Application` — `Active Directory`, `Azure AD`.
- `TargetAccountDisplayName`, `TargetAccountUpn` — the account being acted on.
- `AccountName`, `AccountUpn`, `AccountObjectId` — who did it.
- `DestinationDeviceName`, `DestinationIPAddress`.
- `AdditionalFields` — variant JSON, payload depends on `ActionType`.

**Common predicates**:
```kql
// Privilege escalation — added to Domain Admins
| where ActionType == "Group Membership changed"
| where AdditionalFields has "Domain Admins"

// Forced password reset — common pre-impersonation step
| where ActionType == "Forced password reset"
```

**Gotchas**:
- `AdditionalFields` shape varies per `ActionType` — check Microsoft docs before assuming a field exists.
- Many AAD changes are admin-driven and benign; pair with off-hours / unusual-actor signal.

<!-- ============================================================== -->

## table-IdentityInfo

**Use cases**: identity inventory — used as a join source to enrich logon/sign-in events with role, department, account state.

**Columns that matter**:
- `AccountObjectId`, `AccountUpn`, `AccountSid`, `AccountName`, `AccountDomain`.
- `JobTitle`, `Department`, `Manager`, `City`, `Country`, `OfficeLocation`.
- `IsAccountEnabled` — has the account been disabled?
- `MailAddress`, `Phone`, `EmailAddress`.

**Common pattern — enrich a sign-in with identity context**:
```kql
AADSignInEventsBeta
| where Timestamp > ago(1d) and ErrorCode == 0
| join kind=leftouter (IdentityInfo | project AccountUpn, JobTitle, Department, IsAccountEnabled) on AccountUpn
| where IsAccountEnabled == false                  // sign-in by a disabled account!
```

**Gotchas**:
- Daily-ish snapshot — recently created accounts may not appear yet.

<!-- ============================================================== -->

## table-AlertInfo

**Use cases**: alert-level metadata — title, severity, category, ATT&CK techniques. The "what kind of alert" lookup.

**Columns that matter**:
- `Timestamp`, `AlertId` — primary key, joins to `AlertEvidence`.
- `Title` — same for every alert from the same detection rule.
- `Category` — `Execution`, `LateralMovement`, `Collection`, etc.
- `Severity` — `Informational`, `Low`, `Medium`, `High`.
- `ServiceSource` — `Microsoft Defender for Endpoint`, `Microsoft Defender for Identity`, etc.
- `DetectionSource` — `EDR`, `WindowsDefenderAv`, `AutomatedInvestigation`, `Manual`, etc.
- `AttackTechniques` — array of MITRE technique IDs.

**Common predicates**:
```kql
| where Severity in ("High","Medium")
| where Category == "Execution"
| mv-expand todynamic(AttackTechniques) | extend Technique = tostring(AttackTechniques)
```

<!-- ============================================================== -->

## table-AlertEvidence

**Use cases**: per-entity evidence rows for every alert — the canonical join target for "what entities triggered which alerts".

**Columns that matter**:
- `Timestamp`, `AlertId` — joins to `AlertInfo`.
- `EntityType` — `Machine`, `User`, `Process`, `File`, `Url`, `Ip`, `RegistryKey`, `RegistryValue`, etc.
- `EvidenceRole` — `Impacted`, `Related`.
- `EvidenceDirection` — `Source`, `Destination`.
- `DeviceId`, `DeviceName`, `RemoteIP`, `RemoteUrl`.
- `FileName`, `FolderPath`, `SHA1`, `SHA256`, `FileSize`.
- `AccountName`, `AccountDomain`, `AccountUpn`, `AccountSid`, `AccountObjectId`.
- `ProcessCommandLine`, `ThreatFamily`, `AdditionalFields`.

**Common pattern — alert-context summary**:
```kql
AlertEvidence
| where Timestamp > ago(7d)
| join kind=inner AlertInfo on AlertId
| summarize Count = count(),
            Devices = make_set_if(DeviceName, EntityType == "Machine"),
            Users   = make_set_if(AccountUpn,  EntityType == "User"),
            Files   = make_set_if(FileName,    EntityType == "File")
            by Title, Severity
```

**Gotchas**:
- One alert produces multiple rows (one per entity). Always filter `EntityType` or aggregate via `*_if`.
- Same `Title` may share alert IDs across days — the rule, not the incident.

<!-- ============================================================== -->

## table-CloudAppEvents

**Use cases**: Defender for Cloud Apps (MCAS) audit log — SaaS application activity (Office 365, Salesforce, OneDrive, AWS, GCP, third-party connectors).

**Columns that matter**:
- `Timestamp`, `ActionType` — long enum specific to each app.
- `Application`, `ApplicationId` — the SaaS app.
- `AccountObjectId`, `AccountId`, `AccountDisplayName`, `AccountType`.
- `IsAdminOperation` (bool) — admin-portal action.
- `IPAddress`, `CountryCode`, `City`, `ISP`, `IsAnonymousProxy`.
- `UserAgent`, `DeviceType`, `OSPlatform`.
- `ActivityType`, `ActivityObjects` (dynamic), `ObjectName`, `ObjectType`, `ObjectId`.
- `RawEventData`, `AdditionalFields` — variant JSON; structure depends on `Application`.

**Common predicates**:
```kql
// External-domain user accessing OneDrive
| where Application == "Microsoft OneDrive for Business"
| where AccountDisplayName !endswith "@yourdomain.com"

// Admin-level action from anonymous proxy
| where IsAdminOperation == true and IsAnonymousProxy == true
```

**Gotchas**:
- `ActionType` semantics differ per `Application`. Always group by both before aggregating.
- `RawEventData` shape is app-specific JSON — never assume keys.

<!-- ============================================================== -->

## table-DeviceTvmSoftwareInventory

**Use cases**: Threat-and-Vulnerability-Management software inventory — what's installed where.

**Columns that matter**:
- `DeviceId`, `DeviceName`, `OSPlatform`, `OSVersion`.
- `SoftwareVendor`, `SoftwareName`, `SoftwareVersion`.
- `EndOfSupportStatus`, `EndOfSupportDate`.

**Gotcha**: this is a snapshot, not an event log — `count()` over time is meaningless.

<!-- ============================================================== -->

## table-DeviceTvmSoftwareVulnerabilities

**Use cases**: per-device CVE coverage — which CVE affects which device on which version.

**Columns that matter**:
- `DeviceId`, `DeviceName`, `OSPlatform`, `OSVersion`.
- `SoftwareVendor`, `SoftwareName`, `SoftwareVersion`.
- `CveId`, `VulnerabilitySeverityLevel`.
- `RecommendedSecurityUpdate`, `RecommendedSecurityUpdateId`.

**Common pattern — devices vulnerable to a specific CVE**:
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2024-1234"
| project DeviceName, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate
```

<!-- ============================================================== -->

## table-DeviceTvmSoftwareVulnerabilitiesKB

**Use cases**: CVE knowledge base — CVSS, exploit availability, severity. Reference table without device context.

**Columns that matter**:
- `CveId`, `CvssScore`, `IsExploitAvailable`, `VulnerabilitySeverityLevel`.
- `LastModifiedTime`, `PublishedDate`.

**Gotcha**: no `DeviceId` here — join with `DeviceTvmSoftwareVulnerabilities` on `CveId` for device-scoped views.
