# [HIGH] You Patched LiteLLM, But Do You Know Your AI Blast Radius?

**Source:** Snyk
**Published:** 2026-04-02
**Article:** https://snyk.io/blog/litellm-ai-blast-radius/

## Threat Profile

Snyk Blog In this article
Written by Rudy Lai 
April 2, 2026
0 mins read For a brief window, a widely used open source package in the AI ecosystem was compromised with credential-stealing malware .
LiteLLM , a model gateway used to route requests to more than 100 LLM providers, has been downloaded millions of times per day. In that short window, the malicious versions were likely pulled tens of thousands of times before being caught.
In theory, this should have been reassuring: the project carri…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.203`
- **IPv4 (defanged):** `83.142.209.11`
- **IPv4 (defanged):** `46.151.182.203`
- **Domain (defanged):** `models.litellm.cloud`
- **Domain (defanged):** `checkmarx.zone`
- **Domain (defanged):** `aquasecurtiy.org`
- **Domain (defanged):** `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`
- **Domain (defanged):** `championships-peoples-point-cassette.trycloudflare.com`
- **Domain (defanged):** `investigation-launches-hearings-copying.trycloudflare.com`
- **Domain (defanged):** `souls-entire-defined-routes.trycloudflare.com`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1546** — Event Triggered Execution
- **T1574** — Hijack Execution Flow
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Web Protocols
- **T1027.001** — Binary Padding / Steganography
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.002** — Asymmetric Cryptography (RSA-4096 + AES-256)
- **T1041** — Exfiltration Over C2 Channel
- **T1568.002** — Domain Generation / Lookalike Domains
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1036.005** — Masquerading: Match Legitimate Name (Sysmon)
- **T1610** — Deploy Container
- **T1611** — Escape to Host
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Compromised litellm 1.82.7 / 1.82.8 PyPI install (TeamPCP supply-chain)

`UC_482_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip3.exe","pip","pip3","python.exe","python3.exe","python","python3","uv.exe","uv","poetry.exe","poetry")) AND (Processes.process="*litellm==1.82.7*" OR Processes.process="*litellm==1.82.8*" OR Processes.process="*litellm-1.82.7*" OR Processes.process="*litellm-1.82.8*") by host, user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","pip","pip3","python","python3","uv","uv.exe","poetry","poetry.exe"))
    or (InitiatingProcessFileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","uv.exe","poetry.exe"))
| where ProcessCommandLine has_any ("litellm==1.82.7","litellm==1.82.8","litellm-1.82.7","litellm-1.82.8")
    or InitiatingProcessCommandLine has_any ("litellm==1.82.7","litellm==1.82.8","litellm-1.82.7","litellm-1.82.8")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### litellm_init.pth Python autoload persistence drop

`UC_482_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="litellm_init.pth" OR Filesystem.file_path="*litellm_init.pth*") by host, user, Filesystem.file_path, Filesystem.file_name, Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "litellm_init.pth" or FolderPath has "litellm_init.pth"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### WAV-disguised stager pull from TeamPCP loader 83.142.209.203:8080

`UC_482_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="83.142.209.203" AND All_Traffic.dest_port=8080) by host, All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app, All_Traffic.bytes_out | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteIP == "83.142.209.203" and RemotePort == 8080)
    or (RemoteIP == "83.142.209.203" and (RemoteUrl has ".wav" or RemoteUrl has "/wav"))
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### TeamPCP C2 / exfil egress to models.litellm.cloud, checkmarx.zone and AS205759 nodes

`UC_482_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query IN ("models.litellm.cloud","checkmarx.zone","aquasecurtiy.org","tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io","championships-peoples-point-cassette.trycloudflare.com","investigation-launches-hearings-copying.trycloudflare.com","souls-entire-defined-routes.trycloudflare.com") OR DNS.query="*.models.litellm.cloud" OR DNS.query="*.checkmarx.zone") by host, DNS.src, DNS.query, DNS.answer | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("83.142.209.203","83.142.209.11","46.151.182.203","45.148.10.212") by host, All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("models.litellm.cloud","checkmarx.zone","aquasecurtiy.org","tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io","championships-peoples-point-cassette.trycloudflare.com","investigation-launches-hearings-copying.trycloudflare.com","souls-entire-defined-routes.trycloudflare.com")
    or RemoteIP in ("83.142.209.203","83.142.209.11","46.151.182.203","45.148.10.212")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### Linux user-systemd sysmon persistence drop (~/.config/sysmon/sysmon.py + sysmon.service)

`UC_482_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.config/sysmon/sysmon.py" OR Filesystem.file_path="*/.config/systemd/user/sysmon.service") by host, user, Filesystem.file_path, Filesystem.file_name, Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has "/.config/sysmon/" and FileName =~ "sysmon.py"
    or FolderPath has "/.config/systemd/user/" and FileName =~ "sysmon.service"
    or FolderPath endswith "/.config/sysmon/sysmon.py"
    or FolderPath endswith "/.config/systemd/user/sysmon.service"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### Kubernetes privileged-pod DaemonSet fan-out from compromised LiteLLM workload

`UC_482_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=k8s_audit sourcetype IN ("kube:apiserver:audit","aws:eks:audit","gcp:gke:audit") verb IN ("create","patch") objectRef.resource IN ("pods","daemonsets")
| spath input=requestObject path=spec.containers{}.securityContext.privileged output=privileged_arr
| spath input=requestObject path=spec.hostNetwork output=hostNet
| spath input=requestObject path=spec.hostPID output=hostPid
| spath input=requestObject path=spec.nodeName output=nodeName
| where 'privileged_arr'="true" OR hostNet="true" OR hostPid="true"
| stats dc(nodeName) as NodesTouched, values(objectRef.name) as Pods, min(_time) as firstTime, max(_time) as lastTime by user.username, objectRef.namespace
| where NodesTouched >= 3
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.203`, `83.142.209.11`, `46.151.182.203`, `models.litellm.cloud`, `checkmarx.zone`, `aquasecurtiy.org`, `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`, `championships-peoples-point-cassette.trycloudflare.com` _(+2 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
