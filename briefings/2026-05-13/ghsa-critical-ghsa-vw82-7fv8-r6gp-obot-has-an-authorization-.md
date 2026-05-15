# [CRIT] [GHSA / CRITICAL] GHSA-vw82-7fv8-r6gp: Obot has an authorization bypass in /mcp-connect/{id} that allows any authenticated user to use any registered MCP server

**Source:** GitHub Security Advisories
**Published:** 2026-05-13
**Article:** https://github.com/advisories/GHSA-vw82-7fv8-r6gp

## Threat Profile

Obot has an authorization bypass in /mcp-connect/{id} that allows any authenticated user to use any registered MCP server

## Summary

If you have the MCP Server ID, you can connect to the MCP server even if you don't have permissions to the server.

The MCP gateway endpoint `/mcp-connect/{mcp_id}` does not enforce Access Control Rules (ACRs). Any authenticated Obot user who possesses an MCP Server ID can connect to that server through the gateway — including making tool calls — regardless of wh…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1213** — Data from Information Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Obot /mcp-connect/{id} authenticated-user fan-out (ACR bypass probing)

`UC_62_2` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, dc(Web.url) as DistinctMcpIds, values(Web.url) as SampledUrls, min(_time) as FirstSeen, max(_time) as LastSeen from datamodel=Web.Web where Web.url="*/mcp-connect/*" Web.http_method=POST Web.status=200 by Web.user, Web.src, _time span=10m
| `drop_dm_object_name(Web)`
| rex field=SampledUrls "/mcp-connect/(?<McpId>[^/?\s\"]+)"
| where DistinctMcpIds>=5 AND user!=""
| sort - DistinctMcpIds
```

### [LLM] First-time-seen authenticated user → MCP server ID pairing on /mcp-connect

`UC_62_3` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t min(_time) as FirstSeen, count from datamodel=Web.Web where Web.url="*/mcp-connect/*" Web.http_method=POST Web.status=200 earliest=-30d@d latest=-4h by Web.user, Web.url
| `drop_dm_object_name(Web)`
| rex field=url "/mcp-connect/(?<McpId>[^/?\s\"]+)"
| fields user, McpId
| inputlookup append=t obot_mcp_access_recent.csv
| eval pair=user."|".McpId
| stats count, values(*) as * by pair
| where count==1   // pair only in recent window, not in 30d baseline
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
