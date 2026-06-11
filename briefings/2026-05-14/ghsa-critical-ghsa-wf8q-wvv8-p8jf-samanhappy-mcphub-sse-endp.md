# [CRIT] [GHSA / CRITICAL] GHSA-wf8q-wvv8-p8jf: @samanhappy/mcphub: SSE Endpoint Accepts Arbitrary Username from URL Path Without Authentication, Enabling User Impersonation

**Source:** GitHub Security Advisories
**Published:** 2026-05-14
**Article:** https://github.com/advisories/GHSA-wf8q-wvv8-p8jf

## Threat Profile

@samanhappy/mcphub: SSE Endpoint Accepts Arbitrary Username from URL Path Without Authentication, Enabling User Impersonation

### Summary

A critical identity spoofing vulnerability in MCPHub allows any unauthenticated user to impersonate any other user — including administrators — on SSE (Server-Sent Events) and MCP transport endpoints. The server accepts a username from the URL path parameter and creates an internal user session without any database validation, token verification, or authenti…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1078.003** — Valid Accounts: Local Accounts
- **T1087** — Account Discovery
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### MCPHub SSE endpoint accessed with arbitrary username in URL path (CVE-2025/GHSA-wf8q-wvv8-p8jf hunt)

`UC_281_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agents values(Web.status) as statuses from datamodel=Web where Web.http_method=GET (Web.url="*/sse" OR Web.url="*/sse/*" OR Web.url="*/sse?*") by Web.src Web.dest Web.dest_port Web.url
| `drop_dm_object_name(Web)`
| rex field=url "^(?:https?://[^/]+)?/(?<user_segment>[^/]+)/sse"
| where isnotnull(user_segment) AND NOT user_segment IN ("api","static","assets","health","favicon.ico","robots.txt","_next","public")
| stats min(firstTime) as firstTime max(lastTime) as lastTime values(url) as urls values(user_segment) as user_segments dc(user_segment) as distinct_users count by src dest dest_port
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### MCPHub identity spoofing — admin-themed username in /<user>/sse path

`UC_281_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agents values(Web.status) as statuses from datamodel=Web where Web.http_method=GET (Web.url="*/admin/sse*" OR Web.url="*/administrator/sse*" OR Web.url="*/root/sse*" OR Web.url="*/sudo/sse*" OR Web.url="*/owner/sse*" OR Web.url="*/superuser/sse*" OR Web.url="*/sysadmin/sse*" OR Web.url="*/ceo*/sse*" OR Web.url="*/cfo*/sse*" OR Web.url="*/cto*/sse*" OR Web.url="*/operator/sse*" OR Web.url="*CEO-admin-impersonated*") by Web.src Web.dest Web.dest_port Web.url
| `drop_dm_object_name(Web)`
| rex field=url "^(?:https?://[^/]+)?/(?<user_segment>[^/]+)/sse"
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### MCPHub SSE user-segment fan-out — single source spawning sessions under multiple usernames

`UC_281_2` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where Web.http_method=GET (Web.url="*/sse" OR Web.url="*/sse/*" OR Web.url="*/sse?*") by Web.src Web.dest Web.dest_port Web.url _time span=10m
| `drop_dm_object_name(Web)`
| rex field=url "^(?:https?://[^/]+)?/(?<user_segment>[^/]+)/sse"
| where isnotnull(user_segment) AND NOT user_segment IN ("api","static","assets","health","favicon.ico","_next","public")
| stats dc(user_segment) as distinct_users values(user_segment) as observed_users values(url) as urls min(_time) as firstTime max(_time) as lastTime count by src dest _time
| where distinct_users >= 3
| convert ctime(firstTime) ctime(lastTime)
| sort - distinct_users
```

### MCPHub tool execution via spoofed identity — POST to /<user>/messages with JSON-RPC body

`UC_281_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agents values(Web.status) as statuses values(Web.http_content_type) as content_types from datamodel=Web where Web.http_method=POST (Web.url="*/messages?sessionId=*" OR Web.url="*/messages*sessionId=*") by Web.src Web.dest Web.dest_port Web.url
| `drop_dm_object_name(Web)`
| rex field=url "^(?:https?://[^/]+)?/(?<user_segment>[^/]+)/messages"
| rex field=url "sessionId=(?<session_id>[0-9a-f-]{20,})"
| where isnotnull(user_segment) AND isnotnull(session_id) AND user_segment != "api"
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
