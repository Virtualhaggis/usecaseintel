<!-- curated:true -->
# [HIGH] UNC6692 Impersonates IT Help Desk via Microsoft Teams to Deploy SNOW Malware

**Source:** The Hacker News
**Published:** 2026-04-23
**Article:** https://thehackernews.com/2026/04/unc6692-impersonates-it-helpdesk-via.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

**UNC6692** (Mandiant tracking) is a newly-clustered threat group running the **Microsoft Teams helpdesk impersonation** playbook (paired briefing: 2026-04-18 Microsoft post on cross-tenant helpdesk impersonation). UNC6692's specific signature:
- External Teams chat invitation from `helpdesk@*` / `IT Support` lookalike tenant.
- User accepts → social-engineered to install **custom "SNOW" malware suite**.
- SNOW is described as a custom backdoor (not a public RMM) — distinguishes UNC6692 from Storm-1811 / Octo Tempest who tend to use commodity RMM.

The SNOW family's existence indicates either a **maturing, well-resourced cluster** or a **state-aligned operator** stitching the Teams-helpdesk technique onto a custom toolkit. We've upgraded severity to **HIGH** on three factors:
1. Custom malware (SNOW) means signature-based detection is weak; behaviour-based hunting needed.
2. Teams-helpdesk class is the dominant 2026 social-engineering vector.
3. The TTP is **highly transferable** — UNC6692's recipe will be borrowed by other crews within months.

## Indicators of Compromise

- _SNOW malware sample hashes + C2 endpoints + lookalike tenant names should be in the Mandiant write-up. Pull from the Mandiant blog when available._
- Behavioural shape: external Teams chat with helpdesk-named sender → user clicks a link or downloads a file → custom binary persists via Run-key / scheduled task → C2 over HTTPS to attacker-controlled domain.

## MITRE ATT&CK (analyst-validated)

- **T1566.004** — Phishing: Spearphishing Voice (Teams chat)
- **T1566** — Phishing
- **T1656** — Impersonation
- **T1583.006** — Acquire Infrastructure: Web Services (lookalike tenant)
- **T1219** — Remote Access Software (in some variants)
- **T1204.002** — User Execution: Malicious File
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1071.001** — Application Layer Protocol: Web Protocols (HTTPS C2)

## Recommended SOC actions (priority-ordered)

1. **Block external Teams collaboration** (paired briefing 2026-04-18 has the policy detail). This is the structural fix.
2. **Hunt external Teams chat with helpdesk-named senders** — query below.
3. **Hunt new persistence on user endpoints** in last 30 days — Run-keys and scheduled tasks created under user-context.
4. **Hunt suspicious child-process chains from `Teams.exe` / `ms-teams.exe`** — Teams shouldn't normally launch installers, scripts, or shells.
5. **Cross-correlate**: external Teams chat → file download → process exec within 60 minutes is a high-fidelity intrusion-attempt signature.
6. **End-user training**: show a screenshot of an external Teams chat from an attacker tenant; users need to know what the "External" badge looks like.

## Splunk SPL — external Teams chat from helpdesk-named sender

```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation IN ("MessageSent","ChatCreated","MeetingParticipantsAdded")
  ExternalParticipants=*
| where match(SenderDisplayName,
    "(?i)(help.?desk|it.?support|service.?desk|tech.?support|it.?team|administrator|security.?team|microsoft.?support|onboarding)")
| stats count, dc(RecipientUpn) AS targets, earliest(_time) AS firstTime, latest(_time) AS lastTime,
        values(RecipientUpn) AS recipients
        by SenderUpn, SenderDisplayName, SenderTenant
| sort - count
```

## Splunk SPL — Teams.exe spawning suspicious children

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("Teams.exe","ms-teams.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","mshta.exe","wscript.exe",
                                       "cscript.exe","rundll32.exe","regsvr32.exe","msiexec.exe",
                                       "bitsadmin.exe","certutil.exe","curl.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name,
       Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — new persistence (Run-key / startup folder) on user endpoints

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Registry
    where Registry.action IN ("modified","created")
      AND (Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*"
        OR Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"
        OR Registry.registry_path="*Explorer\\Shell Folders\\Startup*")
      AND NOT Registry.process_name IN ("setup.exe","msiexec.exe","Update.exe","TrustedInstaller.exe")
    by Registry.dest, Registry.process_name, Registry.registry_path,
       Registry.registry_value_name, Registry.registry_value_data, Registry.user
| `drop_dm_object_name(Registry)`
```

## Splunk SPL — Teams-then-download-then-exec chain (60 min)

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created"
      AND Filesystem.file_path="*\\Downloads\\*"
      AND Filesystem.file_name IN ("*.exe","*.msi","*.scr","*.zip","*.iso","*.lnk")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name, _time
| `drop_dm_object_name(Filesystem)`
| join type=inner dest, user
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("Teams.exe","ms-teams.exe","msedge.exe","chrome.exe")
            AND Processes.process_name IN ("powershell.exe","cmd.exe","msiexec.exe")
        by Processes.dest, Processes.user, Processes.process_name, _time]
| eval delta = abs(_time - _time_processes)
| where delta < 3600
```

## Defender KQL — external Teams chat from helpdesk-named sender

```kql
CloudAppEvents
| where Timestamp > ago(60d)
| where Application == "Microsoft Teams"
| where ActionType in ("MessageSent","ChatCreated")
| extend SenderDisplayName = tostring(RawEventData.SenderDisplayName),
         IsExternal = tostring(RawEventData.ExternalParticipants)
| where IsExternal != "" and IsExternal != "[]"
| where SenderDisplayName matches regex
    @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|it.?team|administrator|security.?team|microsoft.?support|onboarding)"
| summarize msgs = count(),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp),
            recipients = make_set(AccountUpn, 50)
            by SenderDisplayName
| order by msgs desc
```

## Defender KQL — Teams.exe child-process anomaly

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("Teams.exe","ms-teams.exe","ms-teamsupdate.exe")
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe",
                       "rundll32.exe","regsvr32.exe","msiexec.exe","bitsadmin.exe",
                       "certutil.exe","curl.exe","wget.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — recent persistence on user endpoints

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("\\CurrentVersion\\Run","\\CurrentVersion\\RunOnce",
                              "Explorer\\Shell Folders\\Startup")
| where InitiatingProcessFileName !in~ ("setup.exe","msiexec.exe","Update.exe","TrustedInstaller.exe")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName,
          RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — Teams chat → download → exec correlation (60 min)

```kql
let teamsChats = CloudAppEvents
    | where Timestamp > ago(30d)
    | where Application == "Microsoft Teams"
    | where ActionType == "MessageSent"
    | where RawEventData has "ExternalParticipants"
    | project ChatTime = Timestamp, AccountUpn;
let downloads = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType == "FileCreated"
    | where FolderPath has "\\Downloads\\"
    | where FileName endswith ".exe" or FileName endswith ".msi"
         or FileName endswith ".scr" or FileName endswith ".iso"
         or FileName endswith ".lnk"
    | project DownloadTime = Timestamp, DeviceName, AccountName, DownloadFile = FileName;
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","cmd.exe","msiexec.exe","mshta.exe")
| join kind=inner downloads on DeviceName
| where Timestamp between (DownloadTime .. DownloadTime + 60m)
| join kind=inner (teamsChats | project AccountUpn, ChatTime) on $left.AccountName == $right.AccountUpn
| where DownloadTime between (ChatTime .. ChatTime + 60m)
| project Timestamp, DeviceName, AccountName, DownloadFile, ChatTime, DownloadTime,
          FileName, ProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

UNC6692 is **proof that the Teams-helpdesk-impersonation playbook is now mature enough to support custom malware** — not just commodity RMM, but bespoke backdoors deployed via this delivery channel. That changes the detection economics: you can't hunt for known RMM binaries; you have to hunt the **chain shape** (external chat → download → exec → persistence). The queries above are the *behavioural backbone* that catches UNC6692 today and the next dozen actors who pick up the playbook tomorrow. The cross-tenant Teams chat block (org policy) is the single most effective control — get it on the change-board agenda this week.
