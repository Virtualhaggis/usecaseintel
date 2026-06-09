# [HIGH] Critical UniFi OS bug lets hackers gain root without authentication

**Source:** BleepingComputer
**Published:** 2026-06-08
**Article:** https://www.bleepingcomputer.com/news/security/critical-unifi-os-bug-lets-hackers-gain-root-without-authentication/

## Threat Profile

Critical UniFi OS bug lets hackers gain root without authentication 
By Bill Toulas 
June 8, 2026
11:51 AM
0 
Attackers can chain three already fixed vulnerabilities in the Ubiquiti UniFi OS server to execute remote code with root privileges and without authentication.
The security issues are tracked as CVE-2026-34908, CVE-2026-34909, and CVE-2026-34910. They have been addressed in May and impact UniFi OS Server versions 5.0.6 and earlier.
While all three flaws received the maximum severity rati…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-34908`
- **CVE:** `CVE-2026-34909`
- **CVE:** `CVE-2026-34910`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1068** — Exploitation for Privilege Escalation
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] UniFi OS CVE-2026-34908/34909 auth bypass via /api/auth/validate-sso/ URI normalization

`UC_26_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src values(Web.http_user_agent) as ua values(Web.status) as status from datamodel=Web.Web where Web.dest_port IN (443,8443,11443) Web.url="*/api/auth/validate-sso/*" (Web.url="*/../*" OR Web.url="*%2e%2e%2f*" OR Web.url="*%2e%2e/*" OR Web.url="*..%2f*" OR Web.url="*ucs/update/latest_package*" OR Web.url="*;*" OR Web.url="*%3b*") by Web.dest Web.src Web.url Web.http_method Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// UniFi appliances typically aren't onboarded to MDE; this query catches Defender-protected Windows reverse proxies fronting UniFi.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (443, 8443, 11443)
| where RemoteIPType == "Public" or LocalIPType == "Public"
| where InitiatingProcessFileName has_any ("nginx.exe","haproxy.exe","caddy.exe","iisexpress.exe","w3wp.exe")
| where AdditionalFields has "/api/auth/validate-sso/"
| where AdditionalFields has_any ("../","%2e%2e%2f","%2e%2e/","..%2f","ucs/update/latest_package",";","%3b")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
```

### [LLM] UniFi OS CVE-2026-34910 command injection via ucs/update/latest_package endpoint

`UC_26_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src values(Web.http_method) as method values(Web.status) as status from datamodel=Web.Web where Web.dest_port IN (443,8443,11443) Web.url="*ucs/update/latest_package*" (Web.url="*;*" OR Web.url="*%3b*" OR Web.url="*|*" OR Web.url="*%7c*" OR Web.url="*`*" OR Web.url="*%60*" OR Web.url="*$(*" OR Web.url="*%24%28*" OR Web.url="*%0a*" OR Web.url="*%26*") by Web.dest Web.src Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Catches Defender-protected reverse proxies (haproxy/nginx on Windows) sitting in front of UniFi appliances
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (443, 8443, 11443)
| where InitiatingProcessFileName has_any ("nginx.exe","haproxy.exe","caddy.exe","w3wp.exe")
| where AdditionalFields has "ucs/update/latest_package"
| where AdditionalFields has_any (";","%3b","|","%7c","`","%60","$(","%24%28","%0a","%26","&&","||")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

### [LLM] Anomalous child processes spawned under UniFi ucs-update service (post-exploitation)

`UC_26_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("ucs-update","ucs","unifi-os") Processes.process_name IN ("bash","sh","dash","zsh","curl","wget","nc","ncat","socat","python","python3","perl","ruby","php","sudo","chmod","chown","base64","openssl","ssh","scp") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Requires Defender for Endpoint on Linux on the UniFi appliance (or a Linux jump host running ucs-update tooling)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("ucs-update","ucs","unifi-os")
| where FileName in~ ("bash","sh","dash","zsh","curl","wget","nc","ncat","socat","python","python3","perl","ruby","php","sudo","chmod","chown","base64","openssl","ssh","scp")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-34908`, `CVE-2026-34909`, `CVE-2026-34910`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
