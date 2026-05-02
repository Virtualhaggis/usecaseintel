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
