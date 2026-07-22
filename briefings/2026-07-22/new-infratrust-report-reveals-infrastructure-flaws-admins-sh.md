# [CRIT] New InfraTrust report reveals infrastructure flaws admins should patch first

**Source:** BleepingComputer
**Published:** 2026-07-22
**Article:** https://www.bleepingcomputer.com/news/security/new-infratrust-report-reveals-infrastructure-flaws-admins-should-patch-first/

## Threat Profile

New InfraTrust report reveals infrastructure flaws admins should patch first 
By Lawrence Abrams 
July 22, 2026
10:15 AM
0 


Eclypsium has launched InfraTrust, a new infrastructure cybersecurity knowledge base and monthly InfraTrust Pulse report designed to help organizations prioritize vulnerabilities affecting infrastructure, firmware, networking, and edge devices.


The monthly report aggregates security advisories from major infrastructure vendors and highlights the vulnerabilities admi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-15409`
- **CVE:** `CVE-2026-15410`
- **CVE:** `CVE-2026-39808`
- **CVE:** `CVE-2026-25089`
- **CVE:** `CVE-2026-21385`
- **CVE:** `CVE-2026-0288`
- **CVE:** `CVE-2026-0287`
- **IPv4 (defanged):** `193.37.32.179`
- **IPv4 (defanged):** `193.37.32.214`
- **IPv4 (defanged):** `216.73.163.151`
- **IPv4 (defanged):** `216.73.163.158`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1068** — Exploitation for Privilege Escalation
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SonicWall SMA1000 pre-auth exploit chain: /wsproxy SSRF + execRemoveHotfix RPC (CVE-2026-15409/15410)

`UC_1_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/wsproxy*" OR Web.url="*remove_hotfix*" OR Web.url="*execRemoveHotfix*") by Web.src Web.dest Web.dest_port Web.http_method Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### SonicWall SMA1000 post-exploit malware artifacts (KNUCKLEBALL / ORANGETAIL / ROOTRUN)

`UC_1_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*deploy_new.py*" OR Processes.process="*agent_wp8.jar*" OR Processes.process="*agent_wp9.jar*" OR Processes.process="*ROOTRUN*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
union
(DeviceFileEvents
 | where Timestamp > ago(14d)
 | where FileName in~ ("deploy_new.py","agent_wp8.jar","agent_wp9.jar")
 | project Timestamp, DeviceName, Kind="FileWrite", Name=FileName, Path=FolderPath, Actor=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine),
(DeviceProcessEvents
 | where Timestamp > ago(14d)
 | where ProcessCommandLine has_any ("deploy_new.py","agent_wp8.jar","agent_wp9.jar","ROOTRUN")
 | project Timestamp, DeviceName, Kind="Process", Name=FileName, Path=FolderPath, Actor=InitiatingProcessFileName, Cmd=ProcessCommandLine)
| sort by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-15409`, `CVE-2026-15410`, `CVE-2026-39808`, `CVE-2026-25089`, `CVE-2026-21385`, `CVE-2026-0288`, `CVE-2026-0287`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `193.37.32.179`, `193.37.32.214`, `216.73.163.151`, `216.73.163.158`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
