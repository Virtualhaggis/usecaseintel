# [HIGH] How StepSecurity Harden Runner Detected Unexpected Microsoft Defender Installation on GitHub-hosted Ubuntu Runners

**Source:** StepSecurity
**Published:** 2025-09-04
**Article:** https://www.stepsecurity.io/blog/how-stepsecurity-harden-runner-detected-unexpected-microsoft-defender-installation-on-github-hosted-ubuntu-runners

## Threat Profile

Back to Blog Threat Intel How StepSecurity Harden Runner Detected Unexpected Microsoft Defender Installation on GitHub-hosted Ubuntu Runners Microsoft Defender was unexpectedly installed on multiple workflow runs from mid-July through mid-August, causing abnormal network traffic. StepSecurity Harden Runner detected this infrastructure anomaly within hours, and GitHub Support has since resolved the issue Varun Sharma View LinkedIn September 2, 2025
Share on X Share on X Share on LinkedIn Share on…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1567** — Exfiltration Over Web Service
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] wdavdaemon or MDE Linux endpoints observed on CI/CD build runners

`UC_653_1` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where (Processes.process_name="wdavdaemon" OR Processes.process="*wdavdaemon*") (Processes.dest IN ("*runner*","*Runner*","*ci-*","*CI-*","*build*","*Build*","*gha-*","*github-actions-*")) by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | append [ | tstats summariesonly=t count values(All_Traffic.url) as url values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("x.cp.wd.microsoft.com","global.endpoint.security.microsoft.com","wdcp.microsoft.com","cdn.x.cp.wd.microsoft.com") OR All_Traffic.url="*x.cp.wd.microsoft.com*" OR All_Traffic.url="*global.endpoint.security.microsoft.com*" OR All_Traffic.url="*wdcp.microsoft.com*") (All_Traffic.src IN ("*runner*","*ci-*","*build*","*gha-*","*github-actions-*")) by All_Traffic.src All_Traffic.dest All_Traffic.url | `drop_dm_object_name(All_Traffic)` ]
```

**Defender KQL:**
```kql
// CI/CD Linux build host running Microsoft Defender daemon (wdavdaemon) or
// contacting MDE cloud endpoints. Real build runners should not be running
// EDR — presence is infrastructure drift (GitHub Aug-2025) or implant.
let CIDevices = DeviceInfo
    | where Timestamp > ago(1d)
    | where OSPlatform == "Linux"
    | where DeviceName matches regex @"(?i)(runner|ci|build|gha|github-actions)"
         or MachineGroup matches regex @"(?i)(runner|ci|build|github)"
    | summarize make_set(DeviceId);
union isfuzzy=true
(   DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where DeviceId in (CIDevices)
    | where FileName =~ "wdavdaemon"
         or InitiatingProcessFileName =~ "wdavdaemon"
         or FolderPath has @"/opt/microsoft/mdatp/"
    | project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
),
(   DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where DeviceId in (CIDevices)
    | where RemoteUrl has_any ("x.cp.wd.microsoft.com",
                                "global.endpoint.security.microsoft.com",
                                "wdcp.microsoft.com",
                                "cdn.x.cp.wd.microsoft.com")
         or InitiatingProcessFileName =~ "wdavdaemon"
    | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
              InitiatingProcessFileName, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### [LLM] CI/CD Linux build host outbound to gist.githubusercontent.com (tj-actions IOC pattern)

`UC_653_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.dest) as dest values(Web.user) as user values(Web.http_user_agent) as ua from datamodel=Web.Web where (Web.url="*gist.githubusercontent.com*" OR Web.url="*gist.github.com*" OR Web.dest="gist.githubusercontent.com" OR Web.dest="gist.github.com") (Web.src IN ("*runner*","*Runner*","*ci-*","*CI-*","*build*","*Build*","*gha-*","*github-actions-*")) by Web.src Web.dest Web.url | `drop_dm_object_name(Web)` | eval tj_actions_payload=if(match(url,"nikitastupin/30e525b776c409e03c2d6f328f254965") OR match(url,"memdump\.py"),"YES","no") | convert ctime(firstTime) ctime(lastTime) | sort - tj_actions_payload firstTime
```

**Defender KQL:**
```kql
// Outbound to gist.githubusercontent.com from CI/CD Linux build hosts — same
// anomaly Harden-Runner used to detect the tj-actions/changed-files compromise
// (CVE-2025-30066, March 2025). The Suspicious_tj column promotes the exact
// malicious payload URL to alerting tier.
let CIDevices = DeviceInfo
    | where Timestamp > ago(1d)
    | where OSPlatform == "Linux"
    | where DeviceName matches regex @"(?i)(runner|ci|build|gha|github-actions)"
         or MachineGroup matches regex @"(?i)(runner|ci|build|github)"
    | summarize make_set(DeviceId);
union isfuzzy=true
(   DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where DeviceId in (CIDevices)
    | where RemoteUrl has_any ("gist.githubusercontent.com","gist.github.com")
    | extend Suspicious_tj_payload = RemoteUrl has "nikitastupin/30e525b776c409e03c2d6f328f254965"
                                  or RemoteUrl has "memdump.py"
    | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              Suspicious_tj_payload
),
(   DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where DeviceId in (CIDevices)
    | where FileName in~ ("curl","wget","python","python3","bash","sh")
    | where ProcessCommandLine has_any ("gist.githubusercontent.com","gist.github.com")
    | extend Suspicious_tj_payload = ProcessCommandLine has "nikitastupin/30e525b776c409e03c2d6f328f254965"
                                  or ProcessCommandLine has "memdump.py"
                                  or ProcessCommandLine has "0e58ed8671d6b60d0890c21b07f8835ace038e67"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              Suspicious_tj_payload
)
| order by Suspicious_tj_payload desc, Timestamp desc
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

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
