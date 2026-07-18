# [HIGH] The Holiday Whisper: Shai-Hulud 3.0

**Source:** Snyk
**Published:** 2025-12-29
**Article:** https://snyk.io/blog/shai-hulud-3-0/

## Threat Profile

Snyk Blog In this article
Written by Lion Kontorer 
December 29, 2025
0 mins read The end-of-year holiday period is traditionally a time for code freezes and quiet rotations; however, it is also a favored window for opportunistic attackers. Threat actors love the holidays; they know that with development teams out of the office and response times naturally lagging, a small window opens for them to test new exploits without immediate detection.
Recently, a security researcher discovered a new, co…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution
- **T1567** — Exfiltration Over Web Service
- **T1567.001** — Exfiltration to Code Repository
- **T1552.001** — Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Compromised npm package @vietmoney/react-big-calendar@0.26.2 installation (Shai-Hulud 3.0)

`UC_695_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("node.exe","npm.cmd","npm.exe","npm","pnpm.cmd","pnpm.exe","pnpm","yarn.cmd","yarn.exe","yarn","bun.exe","bun") OR Processes.parent_process_name IN ("node.exe","npm.cmd","pnpm.cmd","yarn.cmd","bun.exe")) Processes.process="*@vietmoney/react-big-calendar*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | eval malicious_version=if(match(process,"(?i)0\.26\.2"),"YES","unknown") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let pkg = "@vietmoney/react-big-calendar";
let procHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where (FileName in~ ("node.exe","npm.cmd","npm.exe","pnpm.cmd","pnpm.exe","yarn.cmd","yarn.exe","bun.exe"))
         or (InitiatingProcessFileName in~ ("node.exe","npm.cmd","npm.exe","pnpm.cmd","pnpm.exe","yarn.cmd","yarn.exe","bun.exe"))
    | where ProcessCommandLine has pkg or InitiatingProcessCommandLine has pkg
    | extend Evidence = "process", Detail = coalesce(ProcessCommandLine, InitiatingProcessCommandLine)
    | project Timestamp, DeviceName, AccountName, Evidence, Detail, FileName, InitiatingProcessFileName, FolderPath;
let fileHits = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"node_modules\@vietmoney\react-big-calendar" or FolderPath has "node_modules/@vietmoney/react-big-calendar"
    | extend Evidence = "file", Detail = strcat(FolderPath, "\\", FileName)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Evidence, Detail, FileName, InitiatingProcessFileName, FolderPath;
procHits
| union fileHits
| order by Timestamp desc
```

### npm/yarn/pnpm/bun lifecycle hook spawning shell or network LOLBin

`UC_695_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","npm.cmd","pnpm.cmd","yarn.cmd","bun.exe") (Processes.parent_process="*postinstall*" OR Processes.parent_process="*preinstall*" OR Processes.parent_process="*npm-cli.js*" OR Processes.parent_process="*pnpm-cli*" OR Processes.parent_process="*yarn install*" OR Processes.parent_process="*bun install*") (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="cmd.exe" OR Processes.process_name="curl.exe" OR Processes.process_name="wget.exe" OR Processes.process_name="bitsadmin.exe" OR Processes.process_name="certutil.exe" OR Processes.process_name="git.exe" OR Processes.process_name="schtasks.exe" OR Processes.process_name="reg.exe" OR Processes.process_name="bash" OR Processes.process_name="sh" OR Processes.process_name="python.exe" OR Processes.process_name="python") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","pnpm.cmd","yarn.cmd","bun.exe","npm","pnpm","yarn","bun","node")
| where InitiatingProcessCommandLine has_any ("postinstall","preinstall","npm-cli.js","pnpm-cli","yarn install","npm install","npm ci","pnpm install","bun install","run-script")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","wget.exe","bitsadmin.exe","certutil.exe","git.exe","schtasks.exe","reg.exe","bash","sh","python.exe","python","python3")
   or (FileName =~ "node.exe" and ProcessCommandLine has_any (" -e ","--eval","child_process","trufflehog","http.request","https.request"))
| where AccountName !endswith "$"
| extend ParentHook = case(
    InitiatingProcessCommandLine has "postinstall", "postinstall",
    InitiatingProcessCommandLine has "preinstall", "preinstall",
    "install-context")
| project Timestamp, DeviceName, AccountName, ParentHook,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FileName, ChildCmd = ProcessCommandLine,
          FolderPath, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Shai-Hulud 3.0 'Goldox-T3chs' GitHub exfiltration marker observed

`UC_695_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*Goldox-T3chs*" OR Processes.process="*Only Happy Girl*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*Goldox*" OR Filesystem.file_name="*goldox*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`] | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*Goldox-T3chs*" OR Web.http_user_agent="*Goldox*") by Web.src Web.user Web.url Web.dest | `drop_dm_object_name(Web)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let marker = dynamic(["Goldox-T3chs","Only Happy Girl","Goldox"]);
let cloudHits = CloudAppEvents
    | where Timestamp > ago(60d)
    | where Application has_any ("GitHub","github") or ApplicationId == 11161
    | where tostring(RawEventData) has_any (marker) or ObjectName has_any (marker) or tostring(ActivityObjects) has_any (marker)
    | project Timestamp, Source="CloudAppEvents", Application, ActionType, Account=AccountDisplayName, IPAddress, Detail=tostring(RawEventData);
let procHits = DeviceProcessEvents
    | where Timestamp > ago(60d)
    | where ProcessCommandLine has_any (marker) or InitiatingProcessCommandLine has_any (marker)
    | project Timestamp, Source="DeviceProcessEvents", Application=DeviceName, ActionType=FileName, Account=AccountName, IPAddress="", Detail=ProcessCommandLine;
let fileHits = DeviceFileEvents
    | where Timestamp > ago(60d)
    | where FileName has_any (marker) or FolderPath has_any (marker)
    | project Timestamp, Source="DeviceFileEvents", Application=DeviceName, ActionType, Account=InitiatingProcessAccountName, IPAddress="", Detail=strcat(FolderPath,"\\",FileName);
cloudHits | union procHits, fileHits | order by Timestamp desc
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
