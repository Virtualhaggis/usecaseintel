# Datadog Cloud SIEM — query syntax + standard log sources

Concise reference for the `datadog_query` field on every UC.

## Query language at a glance

```
source:<log-source> @<tag.path>:<value> [AND|OR|NOT] @<other.path>:<value>
```

- `source:cloudtrail` — restricts to one log shipper.
- `@user.name:alice` — matches a structured-attribute path. `@` denotes a tagged attribute (case-sensitive path); plain `name:alice` searches free-text.
- Boolean operators: `AND`, `OR`, `NOT` (uppercase). Group with parentheses.
- Wildcards: `@process.name:power*`, `@host:web-*`. Leading wildcards work but are slow.
- Numeric ranges: `@http.status_code:>=400`, `@duration:[100 TO 500]`.
- IP CIDR: `@network.client.ip:81.171.16.0/24`.
- Negation: `-@user.name:svc-*` or `NOT @user.name:svc-*`.
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
- **Wildcards are case-insensitive when written lowercase**; use lowercase except where the protocol specifies otherwise (CloudTrail event names are PascalCase).
- **Group multi-condition queries with parentheses** — `(@a:1 OR @a:2) AND @b:3`.
- **Negation**: `-@user.name:svc-*` or `NOT (@user.name:svc-*)`.
- **CIDR for IPs**: `@network.client.ip:10.0.0.0/8` not regex.

## Examples

```
source:cloudtrail @evt.name:ConsoleLogin @userIdentity.type:Root @evt.outcome:success
```

```
source:windows.sysmon @EventID:1 @ParentImage:*\\winword.exe @Image:(*\\powershell.exe OR *\\mshta.exe OR *\\regsvr32.exe)
```

```
source:azure.activeDirectory @evt.name:"Sign-in activity" @properties.status.errorCode:50126 @network.client.geoip.country.iso_code:(CN OR RU OR IR OR KP)
```

```
source:okta @evt.name:user.account.lock @client.ipAddress:81.171.16.0/24
```

```
source:linux.auditd @auditd.type:EXECVE @process.command_line:(*"chmod +x"* OR *"/tmp/."*) -@process.executable.path:/usr/lib/snapd/*
```
