# [CRIT] Inside the Modern SOC: The 72-Minute Race

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-06-15
**Article:** https://unit42.paloaltonetworks.com/soc-72-minute-race/

## Threat Profile

Threat Research Center 
Insights 
Inside the Modern SOC 
Inside the Modern SOC 
Inside the Modern SOC: The 72-Minute Race 
4 min read 
Related Products Cortex Cortex XSIAM Managed Threat Hunting Unit 42 Incident Response 
By: Sharon Maydar 
Published: June 15, 2026 
Categories: Inside the Modern SOC 
Insights 
Tags: Identity 
Operation security 
Unit 42 Incident Response Report 
The Speed Gap: Where Strategy Meets Reality 
This marks the beginning of our series, Inside the Modern SOC: Trends and…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1621** — Multi-Factor Authentication Request Generation
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1098** — Account Manipulation
- **T1578.002** — Modify Cloud Compute Infrastructure: Create Cloud Instance

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### MFA push fatigue followed by approved sign-in from new IP (Muddled Libra pattern)

`UC_0_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as mfa_failures values(Authentication.src) as failed_ips from datamodel=Authentication where Authentication.action="failure" (Authentication.signature_id="50074" OR Authentication.signature_id="50076" OR Authentication.signature_id="500121" OR Authentication.signature_id="50158") earliest=-7d by Authentication.user _time span=10m | where mfa_failures >= 5 | rename Authentication.user as user, _time as fail_window | join type=inner user [| tstats summariesonly=true earliest(_time) as success_time values(Authentication.src) as success_ip from datamodel=Authentication where Authentication.action="success" earliest=-7d by Authentication.user | rename Authentication.user as user] | where success_time >= fail_window AND success_time <= relative_time(fail_window, "+10m") | eval new_ip=if(isnull(mvfind(failed_ips, success_ip)),"yes","no") | where new_ip="yes" | table fail_window success_time user mfa_failures failed_ips success_ip
```

**Defender KQL:**
```kql
let WindowMin = 10m;
let Threshold = 5;
let Failures = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode in (50074, 50076, 500121, 50158)
    | summarize FailedCount = count(), FailedIPs = make_set(IPAddress) by AccountUpn, FailWindow = bin(Timestamp, WindowMin);
let Successes = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | where AuthenticationRequirement =~ "multiFactorAuthentication"
    | project SuccessTime = Timestamp, AccountUpn, SuccessIP = IPAddress, Country, City, DeviceName, Application;
Failures
| where FailedCount >= Threshold
| join kind=inner Successes on AccountUpn
| where SuccessTime between (FailWindow .. FailWindow + WindowMin)
| where SuccessIP !in (FailedIPs)
| project SuccessTime, AccountUpn, FailedCount, FailedIPs, SuccessIP, Country, City, DeviceName, Application
| order by SuccessTime desc
```

### Global Admin role assigned within 60 min of user's first interactive sign-in

`UC_0_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true earliest(_time) as first_signin from datamodel=Authentication where Authentication.action="success" Authentication.app="Azure Active Directory" earliest=-7d by Authentication.user | rename Authentication.user as user | join type=inner user [| tstats summariesonly=true earliest(_time) as role_assign_time values(All_Changes.object) as role from datamodel=Change where All_Changes.action="modified" All_Changes.change_type="AAA" (All_Changes.object="Global Administrator" OR All_Changes.object="Privileged Role Administrator" OR All_Changes.object="Security Administrator" OR All_Changes.object="Application Administrator" OR All_Changes.object="Cloud Application Administrator") earliest=-7d by All_Changes.user | rename All_Changes.user as user] | eval minutes_elapsed=round((role_assign_time-first_signin)/60,1) | where minutes_elapsed >= 0 AND minutes_elapsed <= 60 | table first_signin role_assign_time minutes_elapsed user role
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowMin = 60m;
let PrivRoles = dynamic(["Global Administrator","Privileged Role Administrator","Security Administrator","Application Administrator","Cloud Application Administrator","Privileged Authentication Administrator"]);
let RoleAdds = CloudAppEvents
    | where Timestamp > ago(LookbackDays)
    | where Application =~ "Office 365" or Application has "Azure"
    | where ActionType in ("Add member to role.","Add eligible member to role.")
    | extend RoleName = tostring(parse_json(tostring(RawEventData)).ModifiedProperties[1].NewValue)
    | extend TargetUpn = tostring(parse_json(tostring(RawEventData)).ObjectId)
    | where RoleName has_any (PrivRoles) or tostring(ActivityObjects) has_any (PrivRoles)
    | project AssignTime = Timestamp, TargetUpn, RoleName, InitiatorUpn = AccountDisplayName;
let FirstSignIn = AADSignInEventsBeta
    | where Timestamp > ago(LookbackDays)
    | where ErrorCode == 0 and IsInteractive == true
    | summarize FirstSignIn = min(Timestamp), FirstIP = arg_min(Timestamp, IPAddress, Country) by AccountUpn;
RoleAdds
| join kind=inner FirstSignIn on $left.TargetUpn == $right.AccountUpn
| where AssignTime between (FirstSignIn .. FirstSignIn + WindowMin)
| extend MinutesElapsed = datetime_diff('minute', AssignTime, FirstSignIn)
| project AssignTime, FirstSignIn, MinutesElapsed, TargetUpn, RoleName, InitiatorUpn, FirstIP, Country
| order by AssignTime desc
```

### VM/disk provisioned by identity elevated to admin in last 24h (rogue cloud asset)

`UC_0_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true earliest(_time) as elevation_time from datamodel=Change where All_Changes.change_type="AAA" All_Changes.action="modified" (All_Changes.object="Global Administrator" OR All_Changes.object="Privileged Role Administrator" OR All_Changes.object="Application Administrator" OR All_Changes.object="Contributor" OR All_Changes.object="Owner") earliest=-7d by All_Changes.dest_user | rename All_Changes.dest_user as elevated_user | join type=inner elevated_user [| tstats summariesonly=true earliest(_time) as vm_create_time values(All_Changes.object) as cloud_object values(All_Changes.src) as caller_ip from datamodel=Change where All_Changes.change_type="Azure" (All_Changes.command="Microsoft.Compute/virtualMachines/write" OR All_Changes.command="Microsoft.Compute/disks/write" OR All_Changes.command="Microsoft.Compute/disks/beginGetAccess/action" OR All_Changes.command="Microsoft.Compute/snapshots/write") earliest=-7d by All_Changes.user | rename All_Changes.user as elevated_user] | eval hours_after_elevation=round((vm_create_time-elevation_time)/3600,1) | where hours_after_elevation >= 0 AND hours_after_elevation <= 24 | table elevation_time vm_create_time hours_after_elevation elevated_user cloud_object caller_ip
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
