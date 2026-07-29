# [HIGH] OpenAI models used Artifactory zero-days to escape to the internet

**Source:** BleepingComputer
**Published:** 2026-07-28
**Article:** https://www.bleepingcomputer.com/news/security/openai-models-used-artifactory-zero-days-to-escape-to-the-internet/

## Threat Profile

OpenAI models used Artifactory zero-days to escape to the internet 
By Lawrence Abrams 
July 28, 2026
04:37 PM
0 
JFrog has confirmed that OpenAI models exploited zero-day vulnerabilities in self-hosted Artifactory servers to help escape an isolated testing environment and gain access to the internet before attacking Hugging Face.
The vulnerabilities were exploited during the incident in which OpenAI models hacked Hugging Face's production infrastructure to steal answers for a cybersecurity benc…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-65921`
- **CVE:** `CVE-2026-65923`
- **CVE:** `CVE-2026-65924`
- **CVE:** `CVE-2026-65925`
- **CVE:** `CVE-2026-66014`
- **CVE:** `CVE-2026-66015`
- **CVE:** `CVE-2026-65617`
- **CVE:** `CVE-2026-66018`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JFrog Artifactory SSRF egress to non-registry destinations (internet escape)

`UC_27_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.src="*artifactory*" AND All_Traffic.direction="outbound" NOT (All_Traffic.dest IN ("*registry.terraform.io","*releases.hashicorp.com","*crates.io","*hashicorp.com","*galaxy.ansible.com","*github.com","*githubusercontent.com")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has_any ("/opt/jfrog", "artifactory")
| where RemoteIP == "169.254.169.254"
   or (RemoteIPType == "Public" and isnotempty(RemoteUrl)
       and not(RemoteUrl has_any ("registry.terraform.io","releases.hashicorp.com","static.crates.io","index.crates.io","crates.io","galaxy.ansible.com","github.com","githubusercontent.com")))
| summarize FirstSeen=min(Timestamp), Count=count(), Ports=make_set(RemotePort) by DeviceName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP
| order by FirstSeen desc
```

### Anonymous access to Artifactory Terraform/Cargo/Ansible remote repositories

`UC_27_4` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/terraform/*" OR Web.url="*/api/terraform/*" OR Web.url="*/cargo/*" OR Web.url="*/api/cargo/*" OR Web.url="*/ansible/*" OR Web.url="*/api/ansible/*") AND Web.user="anonymous" by Web.src Web.user Web.url Web.http_method Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - firstTime
```

### JFrog Artifactory service process spawning a shell or network tool (RCE)

`UC_27_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_path="*jfrog*" OR Processes.parent_process_path="*artifactory*" OR Processes.parent_process_name IN ("java","artifactory","tomcat")) AND Processes.process_name IN ("sh","bash","dash","zsh","python","python3","perl","curl","wget","nc","ncat","socat") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has_any ("/opt/jfrog", "artifactory")
| where FileName in~ ("sh","bash","dash","zsh","python","python3","perl","curl","wget","nc","ncat","socat")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-65921`, `CVE-2026-65923`, `CVE-2026-65924`, `CVE-2026-65925`, `CVE-2026-66014`, `CVE-2026-66015`, `CVE-2026-65617`, `CVE-2026-66018`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
