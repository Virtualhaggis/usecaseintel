# [CRIT] [GHSA / CRITICAL] GHSA-g936-7jqj-mwv8: TSDProxy: Internal proxy auth token forwarded to backend services enables management API escalation

**Source:** GitHub Security Advisories
**Published:** 2026-07-10
**Article:** https://github.com/advisories/GHSA-g936-7jqj-mwv8

## Threat Profile

TSDProxy: Internal proxy auth token forwarded to backend services enables management API escalation

## Description

A vulnerability was discovered in TSDProxy where it forwards its internal per-process authentication token to all proxied backend services. When `identityHeaders` is enabled (the default), tsdproxy injects `x-tsdproxy-auth-token` into every upstream HTTP request alongside user identity headers. This token is the same secret used by the management HTTP server to trust forwarded Tai…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1550.001** — Application Access Token
- **T1068** — Exploitation for Privilege Escalation
- **T1528** — Steal Application Access Token
- **T1562** — Impair Defenses

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TSDProxy management-API replay via injected x-tsdproxy-auth-token to loopback :8080

`UC_8_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*x-tsdproxy-auth-token*" OR Processes.process="*x-tsdproxy-id*") AND (Processes.process="*127.0.0.1:8080*" OR Processes.process="*localhost:8080*" OR Processes.process="*/api/v1*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("x-tsdproxy-auth-token","x-tsdproxy-id")
| where ProcessCommandLine has_any ("127.0.0.1:8080","localhost:8080","/api/v1")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Unexpected process connecting to TSDProxy loopback management port 127.0.0.1:8080

`UC_8_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=8080 AND (All_Traffic.dest="127.0.0.1" OR All_Traffic.dest="::1") AND NOT All_Traffic.process_name="tsdproxy" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 8080
| where RemoteIP in ("127.0.0.1","::1")
| where InitiatingProcessFileName in~ ("curl","wget","python","python3","ruby","node","perl","bash","sh","nc","ncat","socat")
| where InitiatingProcessFileName !in~ ("tsdproxy")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, LocalIP
| order by Timestamp desc
```

### TSDProxy forwarded-token harvesting via header-reflection endpoint or header grep

`UC_8_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*/debug/headers*" OR (Processes.process="*x-tsdproxy-auth-token*" AND (Processes.process="*grep*" OR Processes.process="*awk*" OR Processes.process="*jq*" OR Processes.process="*python*" OR Processes.process="*tcpdump*"))) AND NOT (Processes.process="*127.0.0.1:8080*" OR Processes.process="*/api/v1*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "/debug/headers"
    or (ProcessCommandLine has_any ("x-tsdproxy-auth-token","X-Tsdproxy-Auth-Token")
        and ProcessCommandLine has_any ("grep","awk","jq","python","python3","cut","tcpdump","json.load"))
| where not(ProcessCommandLine has_any ("127.0.0.1:8080","/api/v1"))  // exclude the replay step (UC1)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Inventory of vulnerable TSDProxy deployments (pre-1.4.4 token-forwarding fix)

`UC_8_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="tsdproxy" OR Processes.process="*tsdproxy*" by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "tsdproxy" or SoftwareVendor has "almeidapaulopt"
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, Timestamp
| order by Timestamp desc
// Vulnerable if SoftwareVersion precedes 1.4.4-0.20260603142855-434819b4421e; verify identityHeaders is set to false in the proxy config
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
