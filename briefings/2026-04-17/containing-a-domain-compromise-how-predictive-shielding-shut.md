<!-- curated:true -->
# [HIGH] Containing a Domain Compromise: How Predictive Shielding Shut Down Lateral Movement

**Source:** Microsoft Security Blog
**Published:** 2026-04-17
**Article:** https://www.microsoft.com/en-us/security/blog/2026/04/17/domain-compromise-predictive-shielding-shut-down-lateral-movement/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Microsoft incident-response case study: a domain compromise where the attacker established initial foothold, dumped credentials, and started lateral movement via SMB/admin-share + service-creation, before Defender's "predictive shielding" (essentially attack-path graph + automated containment) cut access. The framing is **product-marketing-shaped but the TTP detail is operationally useful** — the attacker chain matches 80% of human-operated ransomware engagements:

1. Initial access → credential dump (LSASS / SAM / DPAPI) → on-prem AD privilege escalation.
2. Lateral movement via **SMB admin shares + remote service creation** (PsExec / WMI / `sc.exe`).
3. Persistence via RMM install on key servers.
4. Pre-impact discovery (DC enumeration, file-server inventory) before the encryption step that didn't happen because containment fired.

We've upgraded severity to **HIGH** because **lateral-movement-via-SMB-and-service-creation is the most common detection backlog gap** among mid-sized enterprises — Microsoft has documented this pattern as the dominant intrusion shape in 2025-2026, and the queries below are bread-and-butter every SOC needs.

## Indicators of Compromise

- _Microsoft case study — actor unattributed in the public post; specific binaries / hashes / accounts redacted for the customer._
- TTP fingerprints (more useful than IOCs):
  - `sc.exe create ... binPath=...`
  - `wmic /node:<host> process call create`
  - `\\<host>\admin$\<filename>` write
  - `psexesvc.exe` service install on remote target
  - Sudden authentication from one host to >5 servers using a privileged account in <30 min.

## MITRE ATT&CK (analyst-validated)

- **T1021.002** — Remote Services: SMB/Windows Admin Shares
- **T1569.002** — System Services: Service Execution
- **T1078.002** — Valid Accounts: Domain Accounts
- **T1003.001** — OS Credential Dumping: LSASS Memory
- **T1003.002** — OS Credential Dumping: SAM
- **T1219** — Remote Access Software (the attacker's RMM)
- **T1018** — Remote System Discovery (DC / file-server enumeration)

## Recommended SOC actions (priority-ordered)

1. **Build the lateral-movement detection** below if you don't have it — `psexec.exe` / `psexesvc.exe` / `wmic /node:` / SMB admin-share writes are the backbone of human-operated ransomware. Hunt continuously, alert at low thresholds.
2. **LSASS-access detection.** Any non-allowlisted process opening `lsass.exe` is a high-fidelity indicator. Microsoft Defender attack-surface-reduction rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` covers this; ensure it's in audit + block mode.
3. **Privileged-account fan-out detection.** A single account authenticating to >5 endpoints in <30 min is a strong lateral-movement signal.
4. **Restrict SMB admin shares** via GPO where possible (especially for non-admin users — Tier-2 should not have admin$ access to Tier-0).
5. **Enable Microsoft Defender for Identity** if you have Entra licensing — it auto-correlates the on-prem AD lateral-movement signal.
6. **Tabletop exercise** with this TTP chain — most SOCs catch one stage but not the chain.

## Splunk SPL — PsExec / paexec / smbexec lateral movement

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexec64.exe","psexesvc.exe","paexec.exe",
                                       "smbexec.py","CrackMapExec.exe","crackmapexec.exe")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
       OR (Processes.process_name="powershell.exe"
           AND (Processes.process="*Invoke-Command*-ComputerName*"
             OR Processes.process="*New-PSSession*"
             OR Processes.process="*Enter-PSSession*"))
       OR (Processes.process_name="sc.exe"
           AND Processes.process="*\\\\*"
           AND Processes.process="*create*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — LSASS access by non-allowlisted process

```spl
`sysmon` EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage,
    "(?i)(MsMpEng\\.exe|svchost\\.exe|wininit\\.exe|services\\.exe|csrss\\.exe|TaniumClient\\.exe|cb\\.exe|carbon[a-z]+\\.exe|Sentinel[a-z]+\\.exe)")
| stats count, values(SourceImage) AS opener_processes,
        values(GrantedAccess) AS access_masks,
        earliest(_time) AS firstTime
        by Computer, SourceImage
| sort - count
```

## Splunk SPL — privileged-account fan-out

```spl
| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.user_category IN ("admin","privileged","domain-admin")
    by Authentication.user, Authentication.dest, _time span=30m
| `drop_dm_object_name(Authentication)`
| stats dc(dest) AS unique_endpoints, values(dest) AS endpoints,
        sum(count) AS total_auths
        by user, _time
| where unique_endpoints > 5
| sort - unique_endpoints
```

## Splunk SPL — SMB admin-share write activity

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\\admin$\\*"
        OR Filesystem.file_path="*\\c$\\*"
        OR Filesystem.file_path="*\\ipc$\\*")
      AND Filesystem.action IN ("created","modified")
      AND Filesystem.file_name IN ("*.exe","*.dll","*.bat","*.ps1","*.sys","*.scr","*.cmd")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

## Defender KQL — PsExec / WMI / PSRemoting lateral movement

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where (FileName in~ ("psexec.exe","psexec64.exe","psexesvc.exe","paexec.exe",
                        "crackmapexec.exe"))
     or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
     or (FileName =~ "powershell.exe"
         and ProcessCommandLine has_any ("Invoke-Command -ComputerName",
                                          "New-PSSession -ComputerName",
                                          "Enter-PSSession -ComputerName"))
     or (FileName =~ "sc.exe" and ProcessCommandLine has @"\\" and ProcessCommandLine has "create")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — LSASS access (excluding allowlist)

```kql
DeviceEvents
| where Timestamp > ago(60d)
| where ActionType == "OpenProcessApiCall"
| extend Target = tostring(parse_json(AdditionalFields).TargetImageFileName)
| where Target endswith "lsass.exe"
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe","svchost.exe","wininit.exe","services.exe","csrss.exe",
    "TaniumClient.exe","SentinelAgent.exe","SentinelHelperService.exe",
    "cb.exe","carbon-black.exe","cybereason.exe","CrowdStrikeFalconHost.exe",
    "WdSec.exe","CSFalconService.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, Target, AdditionalFields
| order by Timestamp desc
```

## Defender KQL — SMB admin-share file write

```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("\\admin$\\","\\c$\\","\\ipc$\\")
| where FileName endswith ".exe" or FileName endswith ".dll"
     or FileName endswith ".bat" or FileName endswith ".ps1"
     or FileName endswith ".sys" or FileName endswith ".scr"
     or FileName endswith ".cmd"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — privileged account fan-out (5+ devices in 30 min)

```kql
DeviceLogonEvents
| where Timestamp > ago(60d)
| where ActionType == "LogonSuccess"
| where AccountName has_any ("admin","-da","-srv","_admin","_priv")
   or AccountSid has "S-1-5-21-" and AccountName !endswith "$"
| summarize uniqueDevices = dcount(DeviceName),
            devices = make_set(DeviceName, 30),
            logons = count()
            by AccountName, bin(Timestamp, 30m)
| where uniqueDevices > 5
| order by uniqueDevices desc
```

## Why this matters for your SOC

The Microsoft post is a marketing wrapper around a **textbook human-operated ransomware kill chain** caught one stage before encryption. The detection logic is universal — it's not Microsoft-only, it's not even Defender-specific. If your SOC catches **one** stage of the chain (PsExec, LSASS access, fan-out), you have *some* chance of containing the intrusion. If you catch **two stages with auto-correlation**, you have *high* chance. If you catch **three plus auto-block**, you *win*. Build out from the queries above as your detection backbone for the lateral-movement phase. This is bread-and-butter SOC work that pays off across every human-operated intrusion family in 2026.
