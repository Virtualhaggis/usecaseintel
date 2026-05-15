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
- **T1556** — Modify Authentication Process

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] MCPHub SSE endpoint user-impersonation via arbitrary username in URL path (GHSA-wf8q-wvv8-p8jf)

`UC_16_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Web.url) as urls values(Web.http_method) as methods values(Web.http_user_agent) as uas from datamodel=Web where (Web.url="*/sse*" OR Web.url="*/sse/*" OR Web.url="*/messages?sessionId=*") (Web.dest_port=3100 OR Web.url="*/sse*") by Web.src Web.dest Web.url | `drop_dm_object_name(Web)`
| rex field=url "^/(?<spoofed_user>[^/?]+)/(?:sse|messages)"
| where isnotnull(spoofed_user) AND spoofed_user!="api" AND spoofed_user!="health" AND spoofed_user!="static"
| eval is_priv_lookalike=if(match(lower(spoofed_user),"admin|root|administrator|superuser|^ceo|^cfo|^cto|^ciso|impersonat|\\$"),1,0)
| stats values(url) as urls values(methods) as methods values(uas) as user_agents count as hits dc(spoofed_user) as distinct_users values(spoofed_user) as spoofed_users min(firstSeen) as firstSeen max(lastSeen) as lastSeen sum(is_priv_lookalike) as priv_lookalike_hits by src dest
| where priv_lookalike_hits>0 OR distinct_users>=5
| convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
// MCPHub is a server-side npm app; Defender endpoint tables do not expose the request URL path of inbound HTTP to it. Approximate by surfacing inbound connections to port 3100 on hosts that have run @samanhappy/mcphub. Pair with a web-log detection on the actual hunt.
let mcphub_hosts =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "@samanhappy/mcphub" or InitiatingProcessCommandLine has "@samanhappy/mcphub" or ProcessCommandLine has "mcphub"
    | summarize by DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ListeningConnectionCreated","ConnectionSuccess")
| where LocalPort == 3100 or RemotePort == 3100
| where DeviceId in ((mcphub_hosts | project DeviceId))
| where RemoteIPType == "Public"
| summarize Hits = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            Srcs = make_set(RemoteIP, 50),
            UAs = make_set(InitiatingProcessFileName, 10)
            by DeviceName, LocalPort
| order by Hits desc
```

### [LLM] MCPHub vulnerable middleware log line — 'User context set for SSE/MCP endpoint' (spoofed identity created)

`UC_16_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
index=* (source=*mcphub* OR sourcetype=*container* OR sourcetype=*docker* OR sourcetype=*kubernetes*) ("User context set for SSE/MCP endpoint:" OR ("New SSE connection established:" "for user:"))
| rex "User context set for SSE/MCP endpoint:\s+(?<spoofed_user>\S+)"
| rex "New SSE connection established:\s+(?<session_id>[0-9a-f-]{36})\s+with group:\s+(?<group>\S+)\s+for user:\s+(?<sse_user>\S+)"
| eval user = coalesce(spoofed_user, sse_user)
| where isnotnull(user)
| eval is_priv_lookalike=if(match(lower(user),"admin|root|administrator|superuser|^ceo|^cfo|^cto|^ciso|impersonat"),1,0)
| stats min(_time) as firstSeen max(_time) as lastSeen count as events dc(user) as distinct_users values(user) as users values(session_id) as session_ids values(group) as groups sum(is_priv_lookalike) as priv_lookalike_hits by host
| where priv_lookalike_hits>0 OR distinct_users>=5 OR events>=20
| convert ctime(firstSeen) ctime(lastSeen)
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
