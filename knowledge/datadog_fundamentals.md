# Datadog Cloud SIEM — query syntax + standard log sources

Concise reference for the `datadog_query` field on every UC.

## Query language at a glance

```
source:<log-source> @<tag.path>:<value> [AND|OR|NOT] @<other.path>:<value>
```

- `source:cloudtrail` — restricts to one log shipper.
- `@user.name:alice` — matches a structured-attribute path. `@` denotes a tagged attribute; plain `name:alice` is reserved-attribute / free-text.
- **Boolean operators MUST be uppercase**: `AND`, `OR`, `NOT` / `-`. Lowercase `and`/`or` are treated as search terms.
- **All `@attribute` searches are CASE-SENSITIVE**. Direct quote from Datadog docs: *"Attributes searches are case sensitive. Use full-text search to get case insensitive results."* There is no `=~` equivalent. `@Image:*\\dthelper.exe` will NOT match `DTHelper.exe`. See the case-sensitivity guidance in the house-style section below.
- Wildcards: `*` = multi-char, `?` = single-char (incl. space). Both work in tagged attributes (`@process.name:power*`, `@host:web-?`); leading wildcards work but are slow.
- **Wildcards inside quotes are LITERAL** — `"*test*"` searches for asterisks. Always use unquoted values when you need wildcard expansion.
- Numeric ranges: `@http.status_code:>=400`, `@duration:[100 TO 500]`. The bracketed-range form requires the attribute to have a numeric facet.
- **IP CIDR uses the `CIDR()` function, NOT colon syntax**: `CIDR(@network.client.ip, 10.0.0.0/8)` — works for IPv4 and IPv6, accepts multiple ranges `CIDR(@network.client.ip, 10.0.0.0/8, 192.168.0.0/16)`. Do NOT write `@network.client.ip:10.0.0.0/8` — that's a literal-string match and will silently miss everything.
- Negation: `-@user.name:svc-*` or `NOT @user.name:svc-*`.
- Escape these special chars with `\` when matching them literally inside a value: `= - ! && || > >= < <= ( ) { } [ ] " * ? : \ #` and spaces. Forward slash `/` does NOT need escaping. Alternative to escaping: wrap the value in double quotes (which also disables wildcards — pick one approach).
- `@evt.outcome:failure` is a near-universal Datadog convention for failed-action signals.

## Standard log sources we target

The following sources cover the bulk of SOC-relevant detections. Use the source
that matches the article's telemetry. **Don't invent fields** — Datadog
silently returns zero hits for unknown paths.

### `source:cloudtrail` — AWS CloudTrail
- `@evt.name` — event name (e.g. `ConsoleLogin`, `AssumeRole`, `CreateUser`)
- `@userIdentity.type` — `Root`, `IAMUser`, `AssumedRole`, `AWSService`
- `@userIdentity.userName`, `@userIdentity.arn`, `@userIdentity.accountId`
- `@requestParameters.*` — call-specific params (e.g. `userName`, `policyArn`)
- `@responseElements.*` — call response fields
- `@network.client.ip` — caller's source IP
- `@evt.outcome` — `success` / `failure`
- `@aws.region`, `@aws.account.id`

### `source:azure.activity_logs` — Azure subscription / resource activity
- `@operationName.value` (e.g. `Microsoft.Storage/storageAccounts/listKeys/action`)
- `@properties.eventName`, `@properties.activityStatusValue`
- `@identity.claim.upn`, `@identity.claim.appid`
- `@network.client.ip`
- `@properties.resource`, `@resource.resourceGroup`

### `source:azure.activeDirectory` — Entra ID sign-in / audit
- `@evt.name` — `Sign-in activity`, `Add user`, `Update password`
- `@usr.id`, `@usr.email`
- `@user.userPrincipalName`
- `@network.client.ip`, `@network.client.geoip.country.iso_code`
- `@properties.status.errorCode` — sign-in failure code (50053 lockout, 50126 wrong-password)
- `@properties.appDisplayName` — OAuth app name
- `@properties.riskState`, `@properties.riskLevelDuringSignIn`

### `source:windows.security` — Windows Security event channel
- `@EventID` — 4624 logon, 4625 failed logon, 4688 process create, 4720 user added, 4768 TGT
- `@Image` — process image path on 4688 (NewProcessName)
- `@CommandLine` — process commandline on 4688
- `@User`, `@SubjectUserName`, `@TargetUserName`
- `@LogonType` — 2 interactive, 3 network, 10 RDP, etc.
- `@WorkstationName`, `@IpAddress`

### `source:windows.sysmon` — Sysmon (richer than Security 4688)
- `@EventID` — 1 process create, 3 network connect, 7 image load, 11 file create, 13 registry value set
- `@Image`, `@CommandLine`, `@ParentImage`, `@ParentCommandLine`
- `@Hashes` — `MD5=...,SHA256=...,IMPHASH=...`
- `@DestinationIp`, `@DestinationPort`, `@DestinationHostname`
- `@TargetFilename`, `@TargetObject` (registry)
- `@User`, `@LogonId`

### `source:windows.defender` — Microsoft Defender events
- `@EventID` — 1116 detected, 1117 action taken, 5007 config changed
- `@ThreatName`, `@ThreatID`, `@SeverityName`
- `@FilePath`, `@ProcessName`
- `@RemediationAction`, `@DetectionUser`

### `source:linux.auditd` / `source:linux.syslog`
- `@process.name`, `@process.command_line`, `@process.executable.path`
- `@user.name`, `@user.id`
- `@auditd.type` (auditd record type — EXECVE, USER_AUTH, etc.)
- `@network.client.ip`, `@network.destination.ip`
- `@host.name`

### `source:gcp.audit` — Google Cloud audit logs
- `@protoPayload.methodName` — e.g. `google.iam.admin.v1.SetIamPolicy`
- `@protoPayload.authenticationInfo.principalEmail`
- `@protoPayload.requestMetadata.callerIp`
- `@resource.labels.project_id`, `@resource.type`
- `@severity` — `INFO` / `NOTICE` / `WARNING` / `ERROR`

### `source:kubernetes.audit`
- `@verb` — `create`, `update`, `delete`, `exec`, `patch`
- `@objectRef.resource`, `@objectRef.name`, `@objectRef.namespace`
- `@user.username`, `@user.groups`
- `@sourceIPs`
- `@requestObject.spec.*` — pod spec fields when verb=create

### `source:okta` — Okta system log
- `@evt.name` — `user.session.start`, `policy.evaluate_sign_on`, `user.account.lock`
- `@actor.alternateId` (email), `@actor.id`
- `@client.ipAddress`, `@client.geographicalContext.country`
- `@outcome.result` — `SUCCESS` / `FAILURE` / `CHALLENGE`
- `@outcome.reason` — auth-failure reason
- `@authenticationContext.authenticationProvider`

## House style for `datadog_query`

- **Always include `source:`** — without it the query runs against ALL logs and is hopelessly noisy.
- **Prefer `@field.path:exact-value` over free-text search** — Datadog tagged attributes are indexed for fast lookup; free-text matches grep through every log line.
- **Use `evt.outcome` where it exists** — terser than chasing source-specific status codes.
- **Time windows are set at rule level**, not in the query — don't try to encode time in the query.
- **Datadog values are CASE-SENSITIVE** (unlike KQL `=~` / `has`). `@Image:*\\dthelper.exe` will NOT match `DTHelper.exe` and vice versa. There is no case-insensitive operator. To handle vendor-style PascalCase paths plus likely-lowercase variants, emit BOTH casings inside an OR group whenever you reference a binary name, registry key, or other string that could appear in either form:
  - GOOD: `@Image:(*\\DTHelper.exe OR *\\dthelper.exe)`
  - GOOD: `@TargetObject:(*\\Run\\* OR *\\run\\*)`
  - BAD: `@Image:*\\dthelper.exe` (misses real-world `DTHelper.exe` events)
  CloudTrail/AWS event names (`ConsoleLogin`, `AssumeRole`) and Okta event types (`user.session.start`) have a single canonical casing and don't need duplication. Anything that came out of a Windows / Sysmon / file-system path almost certainly does.
- **Group multi-condition queries with parentheses** — `(@a:1 OR @a:2) AND @b:3`.
- **Negation**: `-@user.name:svc-*` or `NOT (@user.name:svc-*)`.
- **CIDR for IPs**: `CIDR(@network.client.ip, 10.0.0.0/8)` — function syntax, NOT `@network.client.ip:10.0.0.0/8` (that's a literal-string match and matches nothing).
- **Reference Tables (lookup lists)** capped at 1,000,000 rows for filtering — fine for our IOC scale, but don't lean on giant allow-lists.
- **Detection-rule queries use the exact same syntax** as the Logs Explorer search bar; time windows, evaluation cadence, groupBy, and aggregation thresholds are configured at rule-level, not in the query string.

## Examples

```
source:cloudtrail @evt.name:ConsoleLogin @userIdentity.type:Root @evt.outcome:success
```

```
source:windows.sysmon @EventID:1 @ParentImage:(*\\winword.exe OR *\\WINWORD.EXE) @Image:(*\\powershell.exe OR *\\PowerShell.exe OR *\\mshta.exe OR *\\MSHTA.EXE OR *\\regsvr32.exe OR *\\RegSvr32.exe)
```

```
source:azure.activeDirectory @evt.name:"Sign-in activity" @properties.status.errorCode:50126 @network.client.geoip.country.iso_code:(CN OR RU OR IR OR KP)
```

```
source:okta @evt.name:user.account.lock CIDR(@client.ipAddress, 81.171.16.0/24)
```

```
source:linux.auditd @auditd.type:EXECVE @process.command_line:(*"chmod +x"* OR *"/tmp/."*) -@process.executable.path:/usr/lib/snapd/*
```
