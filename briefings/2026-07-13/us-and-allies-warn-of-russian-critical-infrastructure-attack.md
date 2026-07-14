# [CRIT] US and allies warn of Russian critical infrastructure attacks

**Source:** BleepingComputer
**Published:** 2026-07-13
**Article:** https://www.bleepingcomputer.com/news/security/us-and-allies-share-defense-tips-against-russian-hackers-targeting-critical-infrastructure/

## Threat Profile

US and allies warn of Russian critical infrastructure attacks 
By Sergiu Gatlan 
July 13, 2026
05:32 AM
0 
Cybersecurity agencies from the United States and eight other countries have issued a joint warning that Russian state hackers are targeting vulnerable and poorly configured routers to infiltrate critical infrastructure networks.
The joint advisory , co-authored by the NSA, FBI, and CISA, along with 15 other agencies from Australia, the United Kingdom , Canada, New Zealand, Estonia, Finland…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2018-0171`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1602.002** — Data from Configuration Repository: Network Device Configuration Dump
- **T1048** — Exfiltration Over Alternative Protocol
- **T1602.001** — Data from Configuration Repository: SNMP (MIB Dump)
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Inbound Cisco Smart Install (TCP/4786) from external hosts — CVE-2018-0171 exploitation

`UC_43_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=4786 (All_Traffic.direction=inbound OR All_Traffic.src_category=external) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | where NOT cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("172.16.0.0/12",src) AND NOT cidrmatch("192.168.0.0/16",src) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 4786
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### TFTP config-file exfiltration from network devices to external servers (UDP/69)

`UC_43_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count sum(All_Traffic.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=69 by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where NOT cidrmatch("10.0.0.0/8",dest) AND NOT cidrmatch("172.16.0.0/12",dest) AND NOT cidrmatch("192.168.0.0/16",dest) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - bytes_out
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 69
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, ActionType, LocalIP, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### External SNMP sweep (UDP/161) probing many internal devices with default/weak community strings

`UC_43_4` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(All_Traffic.dest) as target_count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=161 by All_Traffic.src All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where target_count >= 25 AND NOT cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("172.16.0.0/12",src) AND NOT cidrmatch("192.168.0.0/16",src) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - target_count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 161
| where RemoteIPType == "Public"
| summarize Targets = dcount(RemoteIP), Hits = count(), SampleProc = any(InitiatingProcessFileName) by DeviceName
| where Targets >= 25   // 25 = one host SNMP-touching many external devices = sweep, not routine polling
| order by Targets desc
```

### Endpoint or device beaconing to Static Tundra (FSB Center 16) actor IPs

`UC_43_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port=69 OR All_Traffic.dest_port=161 OR All_Traffic.dest_port=162) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where NOT cidrmatch("10.0.0.0/8",dest) AND NOT cidrmatch("172.16.0.0/12",dest) AND NOT cidrmatch("192.168.0.0/16",dest) | stats count values(dest_port) as dest_ports min(firstTime) as firstTime max(lastTime) as lastTime by src dest | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - count
```

**Defender KQL:**
```kql
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where RemotePort in (69, 161, 162) and RemoteIPType == "Public"
    | summarize by RemoteIP;
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (69, 161, 162)
| where RemoteIPType == "Public"
| join kind=leftanti Baseline on RemoteIP
| summarize FirstSeen = min(Timestamp), Hits = count(), Ports = make_set(RemotePort) by DeviceName, RemoteIP, InitiatingProcessFileName
| order by FirstSeen desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2018-0171`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
