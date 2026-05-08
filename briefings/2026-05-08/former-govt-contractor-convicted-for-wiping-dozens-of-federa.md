# [HIGH] Former govt contractor convicted for wiping dozens of federal databases

**Source:** BleepingComputer
**Published:** 2026-05-08
**Article:** https://www.bleepingcomputer.com/news/security/former-govt-contractor-convicted-for-wiping-dozens-of-federal-databases/

## Threat Profile

Former govt contractor convicted for wiping dozens of federal databases 
By Sergiu Gatlan 
May 8, 2026
04:45 AM
0 


A 34-year-old Virginia man was found guilty of conspiring to destroy dozens of government databases after getting fired from his job as a federal contractor.


In 2016, Sohaib Akhter and his twin brother and co-defendant Muneeb Akhter were also sentenced to several years in prison after pleading guilty to accessing U.S. State Department systems without authorization and steali…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1485** — Data Destruction
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
- **T1490** — Inhibit System Recovery
- **T1078.002** — Valid Accounts: Domain Accounts
- **T1070.004** — Indicator Removal: File Deletion
- **T1561.002** — Disk Wipe: Disk Structure Wipe

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SQL Server mass DROP DATABASE / SET READ_ONLY by single account (Akhter-style insider wipe)

`UC_0_0` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents values(Processes.dest) as dest from datamodel=Endpoint.Processes where Processes.process_name IN ("sqlcmd.exe","osql.exe","powershell.exe","pwsh.exe","SSMS.exe","Microsoft.SqlServer.Management.PowerShell.RunPowerShell.exe") (Processes.process="*DROP DATABASE*" OR Processes.process="*sp_detach_db*" OR Processes.process="*SET READ_ONLY*" OR Processes.process="*sp_cycle_errorlog*" OR Processes.process="*sp_delete_backuphistory*" OR Processes.process="*Remove-SqlDatabase*" OR Processes.process="*Invoke-Sqlcmd*DROP*DATABASE*") by Processes.user Processes.dest _time span=1h | `drop_dm_object_name(Processes)` | stats min(firstTime) as firstTime max(lastTime) as lastTime sum(count) as totalCmds dc(_time) as bucketsHit values(cmdlines) as cmdlines values(parents) as parents by user dest | where totalCmds>=3 | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | sort - totalCmds
```

**Defender KQL:**
```kql
// 3+ destructive SQL statements from one user on one host within a 1h window
let window = 1h;
let sql_clients = dynamic(["sqlcmd.exe","osql.exe","powershell.exe","pwsh.exe","ssms.exe","microsoft.sqlserver.management.powershell.runpowershell.exe"]);
let destructive_tsql = dynamic(["DROP DATABASE","sp_detach_db","SET READ_ONLY","sp_cycle_errorlog","sp_delete_backuphistory","Remove-SqlDatabase"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ (sql_clients)
| where ProcessCommandLine has_any (destructive_tsql)
| extend Statement = case(
    ProcessCommandLine has "DROP DATABASE", "DropDatabase",
    ProcessCommandLine has "SET READ_ONLY", "WriteProtect",
    ProcessCommandLine has "sp_detach_db", "DetachDatabase",
    ProcessCommandLine has "sp_cycle_errorlog", "CycleErrorLog",
    ProcessCommandLine has "sp_delete_backuphistory", "PurgeBackupHistory",
    ProcessCommandLine has "Remove-SqlDatabase", "RemoveSqlDatabase",
    "Other")
| summarize Cmds = count(),
            DistinctActions = dcount(Statement),
            Actions = make_set(Statement),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleCmd = any(ProcessCommandLine)
        by DeviceName, AccountName, bin(Timestamp, window)
| where Cmds >= 3 or DistinctActions >= 2     // any combo of write-protect + drop is high-fidelity
| order by LastSeen desc
```

### [LLM] Windows Server 2012+ event/application log cleared by interactive user account post-destruction

`UC_0_1` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where Processes.user!="*$" Processes.user!="SYSTEM" Processes.user!="LOCAL SERVICE" Processes.user!="NETWORK SERVICE" ((Processes.process_name="wevtutil.exe" AND (Processes.process="*cl *" OR Processes.process="*clear-log*")) OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*Clear-EventLog*" OR Processes.process="*Remove-EventLog*" OR Processes.process="*Limit-EventLog*-RetentionDays 0*" OR Processes.process="*WevtUtil*cl *")) OR (Processes.process_name="fsutil.exe" AND Processes.process="*usn deletejournal*")) by Processes.dest Processes.user Processes.process Processes.parent_process_name _time | `drop_dm_object_name(Processes)` | append [search index=wineventlog (EventCode=1102 OR EventCode=104) | rename Computer as dest, SubjectUserName as user, Channel as process | eval cmdlines="EventLogCleared:".process | table _time dest user process cmdlines parent_process_name] | stats min(firstTime) as firstTime max(lastTime) as lastTime values(cmdlines) as evidence count by dest user | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | where count>=1 | sort - lastTime
```

**Defender KQL:**
```kql
// Defender XDR — process-based + DeviceEvents fallback for log-clear actions
let window = 1h;
let wipe_cmds = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where AccountName !endswith "$"
    | where AccountName !in~ ("system","local service","network service")
    | where (FileName =~ "wevtutil.exe" and (ProcessCommandLine has "cl " or ProcessCommandLine has "clear-log"))
         or (FileName in~ ("powershell.exe","pwsh.exe")
              and (ProcessCommandLine has "Clear-EventLog"
                or ProcessCommandLine has "Remove-EventLog"
                or ProcessCommandLine has "WevtUtil" and ProcessCommandLine has "cl "))
         or (FileName =~ "fsutil.exe" and ProcessCommandLine has "usn" and ProcessCommandLine has "deletejournal")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
              ParentImage = InitiatingProcessFileName,
              IsRemote = IsInitiatingProcessRemoteSession;
// Optional correlation: same user did file/DB deletes in prior 60 min on same host
let destructive = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileDeleted"
    | where InitiatingProcessAccountName !endswith "$"
    | summarize DeletedFiles = count(),
                FirstDelete = min(Timestamp),
                LastDelete  = max(Timestamp)
            by DeviceName, InitiatingProcessAccountName, bin(Timestamp, window)
    | where DeletedFiles >= 25;     // bulk-delete threshold; tune per estate
wipe_cmds
| join kind=leftouter destructive on $left.DeviceName == $right.DeviceName, $left.AccountName == $right.InitiatingProcessAccountName
| extend ProximateBulkDelete = iff(isnotempty(LastDelete) and Timestamp between (LastDelete .. LastDelete + window), true, false)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentImage, IsRemote, ProximateBulkDelete, DeletedFiles
| order by Timestamp desc
```

### [LLM] Company-issued endpoint OS-reinstall / mass wipe by interactive user before device return

`UC_0_2` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where Processes.user!="*$" Processes.user!="SYSTEM" Processes.parent_process_name!="ccmexec.exe" Processes.parent_process_name!="IntuneManagementExtension.exe" ((Processes.process_name="sysprep.exe" AND Processes.process="*/generalize*") OR (Processes.process_name="systemreset.exe" AND (Processes.process="*-factoryreset*" OR Processes.process="*-cleanpc*")) OR (Processes.process_name="cipher.exe" AND Processes.process="*/w:*") OR (Processes.process_name="diskpart.exe" AND Processes.process="*clean*") OR (Processes.process_name="format.com" AND Processes.process="*/q*") OR (Processes.process_name="manage-bde.exe" AND (Processes.process="*-off*" OR Processes.process="*-forcerecovery*")) OR (Processes.process_name="dism.exe" AND Processes.process="*/Apply-Image*") OR (Processes.process_name="reagentc.exe" AND Processes.process="*/boottore*") OR (Processes.process_name="vssadmin.exe" AND Processes.process="*delete shadows*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name _time | `drop_dm_object_name(Processes)` | stats min(firstTime) as firstTime max(lastTime) as lastTime dc(process_name) as distinctTools values(process) as cmdlines values(parent_process_name) as parents sum(count) as count by dest user | where distinctTools>=2 OR count>=3 | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | sort - lastTime
```

**Defender KQL:**
```kql
// Surfaces interactive endpoint-wipe tool clusters; pivot on (Device, Account)
let window = 2h;
let wipe_tools = dynamic(["sysprep.exe","systemreset.exe","cipher.exe","diskpart.exe","format.com","manage-bde.exe","dism.exe","reagentc.exe","vssadmin.exe"]);
let known_mgmt_parents = dynamic(["ccmexec.exe","intunemanagementextension.exe","msiexec.exe","trustedinstaller.exe","taskhostw.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
| where InitiatingProcessFileName !in~ (known_mgmt_parents)
| where FileName in~ (wipe_tools)
| where (FileName =~ "sysprep.exe"     and ProcessCommandLine has "/generalize")
     or (FileName =~ "systemreset.exe" and (ProcessCommandLine has "-factoryreset" or ProcessCommandLine has "-cleanpc"))
     or (FileName =~ "cipher.exe"      and ProcessCommandLine has "/w:")
     or (FileName =~ "diskpart.exe"    and ProcessCommandLine has "clean")
     or (FileName =~ "format.com"      and ProcessCommandLine has "/q")
     or (FileName =~ "manage-bde.exe"  and (ProcessCommandLine has "-off" or ProcessCommandLine has "-forcerecovery"))
     or (FileName =~ "dism.exe"        and ProcessCommandLine has "/Apply-Image")
     or (FileName =~ "reagentc.exe"    and ProcessCommandLine has "/boottore")
     or (FileName =~ "vssadmin.exe"    and ProcessCommandLine has "delete shadows")
| summarize Events = count(),
            DistinctTools = dcount(FileName),
            Tools = make_set(FileName),
            Cmds  = make_set(ProcessCommandLine, 10),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp)
        by DeviceName, AccountName, bin(Timestamp, window)
| where DistinctTools >= 2 or Events >= 3   // tool-cluster heuristic — single sysprep is normal IT
| order by LastSeen desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
