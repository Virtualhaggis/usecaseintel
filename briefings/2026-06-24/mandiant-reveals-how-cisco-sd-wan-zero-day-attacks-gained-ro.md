# [HIGH] Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access

**Source:** BleepingComputer
**Published:** 2026-06-24
**Article:** https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/

## Threat Profile

Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access 
By Lawrence Abrams 
June 24, 2026
05:29 PM
0 
New details have been revealed on how hackers exploited a Cisco Catalyst SD-WAN vulnerability tracked as CVE-2026-20245 in zero-day attacks to create rogue root accounts on targeted devices.
The CVE-2026-20245 vulnerability is a high-severity command injection flaw in Cisco Catalyst SD-WAN Manager (vManage), Controller (vSmart), and Validator (vBond) that allows authenticated atta…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-20245`
- **CVE:** `CVE-2026-20127`
- **CVE:** `CVE-2026-20182`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1136.001** — Create Account: Local Account
- **T1078.003** — Valid Accounts: Local Accounts
- **T1548** — Abuse Elevation Control Mechanism
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1070** — Indicator Removal
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Cisco SD-WAN CVE-2026-20245 exploit via malicious 'evil_tenant.csv' tenant upload

`UC_17_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.object="evil_tenant.csv" by All_Changes.dest All_Changes.user All_Changes.object All_Changes.action All_Changes.command
| `drop_dm_object_name(All_Changes)`
| convert ctime(firstTime) ctime(lastTime)
```

### Rogue root account 'troot' created on Cisco SD-WAN appliance

`UC_17_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.action=created All_Changes.object_category=user All_Changes.object="troot" by All_Changes.dest All_Changes.user All_Changes.object All_Changes.action All_Changes.command
| `drop_dm_object_name(All_Changes)`
| convert ctime(firstTime) ctime(lastTime)
```

### Privilege pivot via 'su' to rogue root account troot on SD-WAN device

`UC_17_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication.Authentication where Authentication.app="su" Authentication.user="troot" by Authentication.dest Authentication.src_user Authentication.user Authentication.app Authentication.action
| `drop_dm_object_name(Authentication)`
| convert ctime(firstTime) ctime(lastTime)
```

### Anti-forensic backup of /etc/passwd and /etc/shadow on SD-WAN appliance

`UC_17_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where (All_Changes.object="/etc/shadow" OR All_Changes.object="/etc/passwd" OR All_Changes.command="*\/etc\/shadow*" OR All_Changes.command="*\/etc\/passwd*") by All_Changes.dest All_Changes.user All_Changes.object All_Changes.action All_Changes.command
| `drop_dm_object_name(All_Changes)`
| convert ctime(firstTime) ctime(lastTime)
```

### Rogue SD-WAN peering / vmanage-admin authentication from unexpected source

`UC_17_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication.Authentication where Authentication.user="vmanage-admin" by Authentication.dest Authentication.src Authentication.user Authentication.app Authentication.action
| `drop_dm_object_name(Authentication)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Article-specific behavioural hunt — Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access

`UC_17_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/etc/shadow*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd", "/etc/shadow"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-20245`, `CVE-2026-20127`, `CVE-2026-20182`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
