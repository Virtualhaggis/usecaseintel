# CrowdStrike Falcon LogScale — query syntax + standard event types

Concise reference for the `falcon_logscale_query` field on every UC.
Falcon LogScale (formerly Humio) is CrowdStrike's NG-SIEM / hunting
query language. This is the dialect the pipeline targets — NOT the
legacy Splunk-style Falcon Insight Event Search.

## Query language at a glance

```
#event_simpleName=ProcessRollup2 ParentBaseFileName=/winrar\.exe/i
| ImageFileName=/(wscript|cscript)\.exe/i
| regex("\\\\(Downloads|Temp)\\\\", field=CommandLine)
| groupBy([aid, ComputerName, ImageFileName], function=count())
| count > 1
```

- `#event_simpleName=X` — equality on the indexed event-type tag. The
  `#` prefix denotes a *tagged field* (faster index lookup). Almost
  every Falcon Data Replicator (FDR) event has an `event_simpleName`
  identifying its schema.
- Free-text fields use plain `Field=value`. Quote the value when it
  contains spaces: `CommandLine="powershell -EncodedCommand"`.
- **Regex matches use `/pattern/i`** (case-insensitive flag is the `i`
  suffix on the slash form). Example: `ImageFileName=/winrar\.exe/i`.
- For substring/contains, use `regex("substring", field=FieldName)`
  inside a filter pipe — easier than escaping slashes for simple cases.
- **Pipe chain order matters**: every `|` reduces the candidate set.
  Put the highest-cardinality filters (`#event_simpleName`, `aid`)
  first so the engine prunes early.
- Aggregation: `| groupBy([field1, field2], function=count())` or
  `| groupBy(field, function={ avg(elapsed) | min(time) })` for
  nested aggregations.
- Time: queries run against the search-bar time window. Inside a
  query, `_time` and `@timestamp` are reserved. Use `_time>=now()-24h`
  only when you need to override the global window.
- Negation: `NOT Field=value` or `Field!=value`. For regex negation:
  `NOT (Field=/pattern/i)`.
- Boolean operators (`AND`, `OR`, `NOT`) are case-sensitive and must
  be uppercase. Lowercase `and`/`or` are treated as field names.
- Wildcards in glob form: `Field="C:\\Users\\*\\Downloads\\*.exe"`.
  Globs work in non-regex contexts; for regex use proper anchors.
- IP filtering: `RemoteAddressIP4=/^10\.0\./` for prefix; for CIDR
  membership use `cidr("10.0.0.0/8", field=RemoteAddressIP4)`.

## Standard event types we target

CrowdStrike FDR ships hundreds of `event_simpleName` values; here are
the ones SOC detections care about most. Use the event type that
matches the article's telemetry. **Don't invent event names** — they
silently return zero rows.

### `#event_simpleName=ProcessRollup2`
Aggregated process creation. The bread and butter of EDR detections.
Key fields:
- `aid` — agent identifier (CrowdStrike host UUID)
- `ComputerName`, `UserName`, `UserSid`
- `ImageFileName` — full path of the executed binary
- `CommandLine` — full command line including args
- `ParentBaseFileName` — parent process name only (e.g. `winrar.exe`)
- `ParentImageFileName` — parent process full path
- `TargetProcessId`, `RawProcessId`
- `SHA256HashData`, `MD5HashData`, `SHA1HashData` — hashes of the
  executed image
- `IntegrityLevel` — Low / Medium / High / System
- `TokenType` — Primary / Impersonation
- `AuthenticationId` — logon session ID for attaching to logon events
- `SignInfoFlags`, `ImageSubsystem` — signing/subsystem context

### `#event_simpleName=SyntheticProcessRollup2`
Same shape as ProcessRollup2 but synthesised from script execution
context. Use when targeting wscript.exe / cscript.exe / mshta.exe
spawning JS/VBS — the synthetic record carries the script body in
`CommandLine`.

### `#event_simpleName=DnsRequest`
DNS resolution attempts. Key fields:
- `aid`, `ComputerName`
- `DomainName` — the queried domain (lower-case)
- `RequestType` — `A`, `AAAA`, `MX`, `TXT`, etc.
- `FirstIP4Record`, `IpAddress` — resolved IP if any
- `ContextProcessId` — process that triggered the DNS request
- `ContextImageFileName` — executable that initiated

### `#event_simpleName=NetworkConnectIP4` (and IP6)
Outbound network connections at the EDR layer.
- `aid`, `ComputerName`
- `RemoteAddressIP4` / `RemoteAddressIP6`
- `RemotePort`, `LocalAddressIP4`, `LocalPort`
- `Protocol` — TCP=6, UDP=17 (numeric)
- `ConnectionFlags`, `ConnectionDirection`
- `ContextProcessId`, `ContextImageFileName` — the process making the
  connection

### `#event_simpleName=FileWritten` (and FileOpenInfo, FileDeleted)
File-system activity. Watch for ransomware extensions, malicious
payload drops, persistence file writes.
- `aid`, `ComputerName`
- `TargetFileName` — full path of the written/opened file
- `ContextImageFileName` — process doing the write
- `ContextProcessId`
- `WrittenBytes` — only on FileWritten
- `FileObjectExtension`, `MajorFunction`, `MinorFunction`

### `#event_simpleName=AsepValueUpdate`
Registry autostart (Run keys, Services, BHO, COM, etc.) — the textbook
persistence telemetry source.
- `aid`, `ComputerName`
- `RegObjectName` — the registry key path
- `RegValueName` — the value name
- `RegStringValue` — value contents (the command that auto-runs)
- `RegOperationType`
- `ContextImageFileName`, `ContextProcessId` — the process that wrote
  the autostart entry

### `#event_simpleName=ScriptControlScanInfo`
PowerShell / VBScript / JScript content captured before execution
(AMSI integration). Carries the actual script body.
- `aid`, `ComputerName`
- `ScriptContent` — the raw script text
- `HostName` — host application (powershell.exe / wscript.exe / etc.)
- `Scope` — execution policy scope

### `#event_simpleName=UserLogon` / `UserLogoff`
Authentication events.
- `aid`, `ComputerName`, `UserName`, `UserPrincipal`, `UserSid`
- `LogonType` — Interactive=2, Network=3, Batch=4, Service=5,
  Unlock=7, RemoteInteractive=10
- `RemoteAccount`, `RemoteAddressIP4` — for remote logons
- `LogonTime`, `AuthenticationPackage`

### `#event_simpleName=DllInjection`
Process-injection telemetry.
- `aid`, `ComputerName`
- `TargetImageFileName`, `TargetProcessId` — the victim process
- `ContextImageFileName`, `ContextProcessId` — the injector

### Cloud / Identity (CrowdStrike Falcon Identity Protection)
- `#event_simpleName=IdpAuthenticationLog` — Azure AD / Okta /
  Entra sign-in events when the Identity Protection module ships them
  to FDR.
- `#event_simpleName=IdpDomainController` — domain controller auth
  context.

## House-style guidance for `falcon_logscale_query`

- **Lead with `#event_simpleName=X`** so the engine prunes to one
  schema fast. Without it, the query scans every event type.
- **Filter on `aid`** if the detection should be per-host; group by
  `aid` for cross-host hunting.
- **Use regex with `/i`** for case-insensitive binary/path matches:
  `ImageFileName=/(wscript|cscript)\.exe$/i`.
- **Don't `groupBy` without a `function=`** — the engine errors.
  Common: `count()`, `count(field=aid, distinct=true)`, `min(_time)`,
  `max(_time)`.
- **Comments use `//`** at end of line, NOT `#` (which is the tag
  prefix).
- **Path separators** in Windows fields: `\\` in regex strings,
  literal `\\` (double backslash) in unquoted glob strings:
  `ImageFileName="C:\\Windows\\System32\\*.exe"`.
- For temporal-correlation (parent-spawned-child within N seconds),
  Falcon LogScale uses `join({...subquery...}, field=aid)` rather
  than Splunk's `transaction`. Subqueries chain with their own pipe.

## Anti-patterns

- ❌ `event_simpleName=ProcessRollup2` (missing `#` — slow, scans all)
- ❌ `CommandLine=*powershell*` (don't put wildcards inside unquoted
  values — quote and use regex instead)
- ❌ `where ... | regex(...)` — there's no `where`; filters chain via
  bare `|` with a predicate
- ❌ Splunk-style `eval`, `rex`, `stats` — those are Splunk SPL, not
  LogScale. The LogScale equivalents are `:=` assignment, `regex()`,
  and `groupBy()`.
- ❌ Confusing `#event_simpleName` with `#event_platform` — the
  latter is OS, the former is event schema.
