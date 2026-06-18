# [CRIT] [GHSA / CRITICAL] GHSA-j4f3-55x4-r6q2: npm PraisonAI MCPServer exposes unauthenticated HTTP tools/call

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-j4f3-55x4-r6q2

## Threat Profile

npm PraisonAI MCPServer exposes unauthenticated HTTP tools/call

## Summary

The published npm package `praisonai` exports a TypeScript `MCPServer` that can expose tools, resources, and prompts over an HTTP JSON-RPC transport with:

```ts
await server.start({ port: 3000 });
```

The HTTP transport has no authentication or authorization path. `MCPServerConfig` does not expose an auth/security setting, `startHttp()` ignores the `Authorization` header, and every POST request is parsed and forwarded…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — JavaScript
- **T1059.001** — PowerShell
- **T1059.003** — Windows Command Shell
- **T1059.004** — Unix Shell
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated JSON-RPC tools/call hitting an internal MCP HTTP listener

`UC_21_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as method values(Web.url) as url values(Web.user_agent) as ua from datamodel=Web.Web where Web.dest_port=3000 AND Web.http_method=POST AND (Web.url="*" OR Web.uri_path="*") by Web.src Web.dest Web.dest_port Web.http_method | `drop_dm_object_name(Web)` | join type=inner src dest [ search index=proxy OR index=waf OR sourcetype=cisco:asa OR sourcetype=stream:http dest_port=3000 ("\"method\":\"tools/call\"" OR "\"method\":\"tools/list\"" OR "\"method\":\"resources/read\"" OR "\"method\":\"prompts/get\"") | rex field=_raw "Authorization:\s*(?<auth>Bearer\s+\S+)?" | eval auth_missing=if(isnull(auth) OR auth="" OR match(auth,"(?i)bearer\s+invalid"),1,0) | where auth_missing=1 | stats values(auth) as auth_header by src dest ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 3000
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has_any ("praisonai", "praisonai-ts", "mcp/server", "MCPServer")
| where RemoteIPType !in ("Loopback", "Private") or RemoteIP !in ("127.0.0.1", "::1")
| project Timestamp, DeviceName, RemoteIP, RemoteIPType, LocalIP, LocalPort,
          InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Vulnerable praisonai npm package (<=1.7.1) installed on host

`UC_21_3` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\praisonai\\package.json" OR Filesystem.file_path="*/node_modules/praisonai/package.json" OR Filesystem.file_path="*\\praisonai-ts\\src\\mcp\\server.ts" OR Filesystem.file_path="*/praisonai-ts/src/mcp/server.ts") by Filesystem.dest Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileRenamed")
| where FolderPath has "node_modules\\praisonai" or FolderPath has "node_modules/praisonai" or FolderPath has "praisonai-ts\\src\\mcp" or FolderPath has "praisonai-ts/src/mcp"
| where FileName in~ ("package.json", "server.ts", "server.js")
| where InitiatingProcessFileName in~ ("npm.exe", "npm-cli.js", "node.exe", "pnpm.exe", "yarn.exe", "corepack.exe")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Node.js praisonai MCP server spawning shell or scripting interpreter (tool-call abuse)

`UC_21_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name=node.exe OR Processes.parent_process_name=node) (Processes.process_name=cmd.exe OR Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe OR Processes.process_name=bash OR Processes.process_name=sh OR Processes.process_name=wscript.exe OR Processes.process_name=cscript.exe) (Processes.parent_process=*praisonai* OR Processes.parent_process=*MCPServer* OR Processes.parent_process=*mcp/server*) by Processes.dest Processes.parent_process_name Processes.process_name Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has_any ("praisonai", "praisonai-ts", "MCPServer", "mcp/server", "mcp\\server")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "wsl.exe", "sh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "curl.exe", "certutil.exe", "bitsadmin.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-j4f3-55x4-r6q2: npm PraisonAI MCPServer exposes unauthent

`UC_21_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-j4f3-55x4-r6q2: npm PraisonAI MCPServer exposes unauthent ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-j4f3-55x4-r6q2: npm PraisonAI MCPServer exposes unauthent
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 5 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
