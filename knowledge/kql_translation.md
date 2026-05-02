# Defender XDR ↔ Sentinel translation reference

Both speak KQL — same operators, same data types. What differs is the
**schema**: which table holds what data, what each column is named,
and what the timestamp field is called. This file is the rosetta
stone for porting a query from one tenant to the other.

<!-- ============================================================== -->

## translation-universals

These differences apply across **every** table:

| Concept             | Defender XDR (Advanced Hunting) | Sentinel                   |
|---------------------|---------------------------------|----------------------------|
| Timestamp column    | `Timestamp`                      | `TimeGenerated`            |
| Default time-bound  | `Timestamp > ago(1h)`            | `TimeGenerated > ago(1h)`  |
| Resource id         | not used                         | `_ResourceId`              |
| Computer / device   | `DeviceName`, `DeviceId`         | `Computer` (Windows), `DvcHostname` (ASIM) |
| Tenant id           | implicit                         | `_BillableTenantId` (sometimes) |

> **One change every port needs**: rename `Timestamp` → `TimeGenerated`
> in every `where` and `project`.

<!-- ============================================================== -->

## translation-process-events

Same goal, different tables:

| Defender XDR `DeviceProcessEvents`        | Sentinel `SecurityEvent` (EventID 4688)     | Sentinel ASIM `ImProcessCreate` |
|-------------------------------------------|----------------------------------------------|---------------------------------|
| `Timestamp`                                | `TimeGenerated`                              | `TimeGenerated`                 |
| `DeviceName`                               | `Computer`                                   | `DvcHostname`                   |
| `AccountName`                              | `Account` (`domain\user`) or `AccountName`   | `ActorUsername`                 |
| `AccountDomain`                            | `AccountDomain`                              | (split from `ActorUsername`)    |
| `FileName`                                 | `NewProcessName` (full path)                 | `TargetProcessName`             |
| `FolderPath`                               | derive from `NewProcessName`                 | (in `TargetProcessName`)        |
| `ProcessCommandLine`                       | `CommandLine`                                | `TargetProcessCommandLine`      |
| `ProcessId`                                | `NewProcessId`                               | `TargetProcessId`               |
| `InitiatingProcessFileName`                | `ParentProcessName` (full path)              | `ParentProcessName`             |
| `InitiatingProcessCommandLine`             | not in 4688 (only newer connectors)          | `ParentProcessCommandLine`      |
| `InitiatingProcessId`                      | `ProcessId`                                  | `ParentProcessId`               |
| `InitiatingProcessAccountName`             | `SubjectUserName`                            | (use `ActorUsername`)           |
| `SHA256` / `SHA1` / `MD5`                  | `FileHash` (one column, type-tagged)         | `SHA256` / `SHA1` / `MD5`       |

### Defender → Sentinel SecurityEvent example

```kql
// Defender
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName =~ "outlook.exe"
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

```kql
// Sentinel SecurityEvent
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688              // process-create
| where Account !endswith "$"
| where ParentProcessName endswith "outlook.exe"
| where NewProcessName endswith "powershell.exe"
| project TimeGenerated, Computer, Account, CommandLine
```

```kql
// Sentinel ASIM (cross-connector)
ImProcessCreate
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where ParentProcessName =~ "outlook.exe"
| where TargetProcessName =~ "powershell.exe"
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessCommandLine
```

<!-- ============================================================== -->

## translation-network-events

| Defender `DeviceNetworkEvents`             | Sentinel `CommonSecurityLog` (CEF FW)        | Sentinel ASIM `ImNetworkSession` |
|--------------------------------------------|----------------------------------------------|-----------------------------------|
| `Timestamp`                                | `TimeGenerated`                              | `TimeGenerated`                   |
| `DeviceName`                               | `DeviceName` (FW name) / `Computer`          | `DvcHostname`                     |
| `LocalIP`                                  | `SourceIP` (depends on direction)            | `SrcIpAddr`                       |
| `LocalPort`                                | `SourcePort`                                 | `SrcPortNumber`                   |
| `RemoteIP`                                 | `DestinationIP`                              | `DstIpAddr`                       |
| `RemotePort`                               | `DestinationPort`                            | `DstPortNumber`                   |
| `RemoteUrl`                                | `RequestURL`                                 | `Url`                             |
| `RemoteIPType` (`Public`/`Private`)        | derive via `ipv4_is_private(DestinationIP)`  | derive via `ipv4_is_private(DstIpAddr)` |
| `Protocol`                                 | `Protocol`                                   | `NetworkProtocol`                 |
| `ActionType` (`ConnectionSuccess` etc.)    | `DeviceAction` (`allow`/`deny`/`drop`)       | `DvcAction`                       |
| `InitiatingProcessFileName`                | not on FW logs; on EDR connector only        | `ActingProcessName`               |

<!-- ============================================================== -->

## translation-aad-signins

| Defender XDR `AADSignInEventsBeta`         | Sentinel `SigninLogs`                                 |
|--------------------------------------------|--------------------------------------------------------|
| `Timestamp`                                | `TimeGenerated`                                        |
| `AccountUpn`                               | `UserPrincipalName`                                    |
| `AccountDisplayName`                       | `UserDisplayName`                                      |
| `AccountObjectId`                          | `UserId`                                               |
| `Application`                              | `AppDisplayName`                                       |
| `ApplicationId`                            | `AppId`                                                |
| `ResourceId` (Graph: `00000003-...`)       | `ResourceId`                                           |
| `IPAddress`                                | `IPAddress`                                            |
| `Country`, `City`, `State`                 | derive from `tostring(parse_json(LocationDetails).countryOrRegion)` etc. |
| `ErrorCode` (`50053`, `50126`, ...)        | `ResultType`                                           |
| `ClientAppUsed`                            | `ClientAppUsed` (same)                                 |
| `ConditionalAccessStatus`                  | `ConditionalAccessStatus`                              |
| `IsAnonymousProxy`                         | not promoted to a column; check `RiskEventTypes_V2`    |
| `RiskLevelDuringSignIn`                    | `RiskLevelDuringSignIn`                                |
| `MfaDetail` (JSON)                         | `MfaDetail` (JSON, but different keys)                 |
| `IsExternalUser`                           | derive via `UserPrincipalName has "#EXT#"`             |

### Impossible-travel — both sides

```kql
// Defender XDR
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where isnotempty(Country)
| project Timestamp, AccountUpn, Country, IPAddress
| order by AccountUpn asc, Timestamp asc
| extend Prev = prev(Country), PrevTime = prev(Timestamp), PrevAcct = prev(AccountUpn)
| where AccountUpn == PrevAcct and Country != Prev
   and datetime_diff('minute', Timestamp, PrevTime) <= 60
```

```kql
// Sentinel
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| where isnotempty(Country)
| project TimeGenerated, UserPrincipalName, Country, IPAddress
| order by UserPrincipalName asc, TimeGenerated asc
| extend Prev = prev(Country), PrevTime = prev(TimeGenerated), PrevAcct = prev(UserPrincipalName)
| where UserPrincipalName == PrevAcct and Country != Prev
   and datetime_diff('minute', TimeGenerated, PrevTime) <= 60
```

<!-- ============================================================== -->

## translation-email

Defender XDR has dedicated email tables; Sentinel collects via the
**OfficeActivity** connector (Exchange workload).

| Defender                       | Sentinel `OfficeActivity` (Exchange)              |
|--------------------------------|---------------------------------------------------|
| `EmailEvents.Subject`          | `Subject`                                         |
| `EmailEvents.SenderFromAddress`| `Sender`                                          |
| `EmailEvents.RecipientEmailAddress` | `Recipients` (string-array), `MailboxOwnerUPN` |
| `EmailEvents.DeliveryAction`   | `DeliveryAction`                                  |
| `EmailEvents.NetworkMessageId` | `MessageId` / `InternetMessageId`                 |
| `UrlClickEvents`               | not in OfficeActivity — needs Defender for Office connector or `EmailUrlInfo` projection |
| `EmailAttachmentInfo.SHA256`   | not directly available — pivot to file-event tables on the recipient host |

> **Honest take**: Sentinel's email visibility via `OfficeActivity` is
> coarser than Defender's. For end-to-end phishing-to-execution chains,
> connect MDE → Sentinel and join via `DeviceProcessEvents`.

<!-- ============================================================== -->

## translation-identity-windows-auth

| Defender XDR `IdentityLogonEvents`       | Sentinel `SecurityEvent` (4624 / 4625) |
|------------------------------------------|----------------------------------------|
| `AccountUpn`                             | derive from `Account` + UPN suffix lookup |
| `AccountName`, `AccountDomain`           | `AccountName`, `AccountDomain` / `Account` |
| `ActionType` `LogonSuccess` / `LogonFailed` | `EventID` 4624 / 4625                  |
| `LogonType` (string `Interactive` etc.)  | `LogonType` (int) + `LogonTypeName` (string) |
| `Protocol` (`Kerberos` / `NTLM`)         | `AuthenticationPackageName`            |
| `IPAddress`                              | `IpAddress`                            |
| `FailureReason`                          | `FailureReason`                        |
| `IsLocalAdmin`                           | not directly — derive via `MemberOf` enrichment |

<!-- ============================================================== -->

## translation-file-events

| Defender `DeviceFileEvents`     | Sentinel ASIM `ImFileEvent`            |
|---------------------------------|----------------------------------------|
| `Timestamp`                     | `TimeGenerated`                        |
| `DeviceName`                    | `DvcHostname`                          |
| `ActionType` (`FileCreated`...) | `EventType` (`FileCreated`...) + `EventResult` |
| `FileName`                      | `TargetFileName`                       |
| `FolderPath`                    | `TargetFilePath`                       |
| `SHA256` / `SHA1` / `MD5`       | `TargetFileSHA256` / `SHA1` / `MD5`    |
| `InitiatingProcessFileName`     | `ActingProcessName`                    |
| `InitiatingProcessAccountName`  | `ActorUsername`                        |

<!-- ============================================================== -->

## translation-registry-events

| Defender `DeviceRegistryEvents`     | Sentinel ASIM `ImRegistryEvent`         |
|-------------------------------------|------------------------------------------|
| `RegistryKey`                       | `RegistryKey`                            |
| `RegistryValueName`                 | `RegistryValue`                          |
| `RegistryValueData`                 | `RegistryValueData`                      |
| `RegistryValueType`                 | `RegistryValueType`                      |
| `ActionType`                        | `EventType` + `EventResult`              |
| `InitiatingProcessFileName`         | `ActingProcessName`                      |

<!-- ============================================================== -->

## translation-cheat-sheet

When porting **fast**, run these substitutions in order:

  1. `Timestamp` → `TimeGenerated`
  2. `DeviceProcessEvents` → `SecurityEvent | where EventID == 4688` (or `ImProcessCreate`)
  3. `DeviceNetworkEvents` → `ImNetworkSession` (or `CommonSecurityLog` for FW logs)
  4. `DeviceFileEvents` → `ImFileEvent`
  5. `DeviceRegistryEvents` → `ImRegistryEvent`
  6. `IdentityLogonEvents` → `SecurityEvent | where EventID in (4624, 4625)`
  7. `AADSignInEventsBeta` → `SigninLogs`
  8. `EmailEvents` → `OfficeActivity | where OfficeWorkload == "Exchange"`
  9. `AccountUpn` → `UserPrincipalName` (in AAD context)
 10. `AccountName !endswith "$"` → same predicate, but on the field name from the table above.

> **Schema-validate** the result with `python kql_schema_validator.py
> <port.kql>` — both schemas are loaded simultaneously, so any field
> that exists on neither platform will get flagged.
