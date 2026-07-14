# [HIGH] Why npm lockfiles can be a security blindspot for injecting malicious modules

**Source:** Snyk
**Published:** 2019-09-24
**Article:** https://snyk.io/blog/why-npm-lockfiles-can-be-a-security-blindspot-for-injecting-malicious-modules/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
September 24, 2019
0 mins read I recently started playing around with the idea of threat modeling packages on the npm ecosystem. Can an event-stream incident happen again? How about other supply chain attacks? What will be the next vector of attack that we haven’t seen yet and might it be entirely preventable?
And then, one day I had a eureka! ? Let me show you how easy it is to introduce back doors that are easily missed by project owners… leaving…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059** — Command and Scripting Interpreter
- **T1546.016** — Installer Packages

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm/yarn dependency fetched from non-registry source (lockfile resolved-URL hijack)

`UC_3453_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*/tarball/*" AND (Web.http_user_agent="npm/*" OR Web.http_user_agent="yarn/*" OR Web.http_user_agent="pnpm/*") AND NOT (Web.dest="registry.npmjs.org" OR Web.dest="registry.yarnpkg.com") by Web.src Web.user Web.dest Web.site Web.url Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe")
| where isnotempty(RemoteUrl)
| where RemoteUrl has "/tarball/"
    or RemoteUrl has_any ("github.com","raw.githubusercontent.com","gitlab.com","bitbucket.org")
    or (RemoteUrl has "registry." and RemoteUrl !has "registry.npmjs.org" and RemoteUrl !has "registry.yarnpkg.com")
| where RemoteUrl !has "registry.npmjs.org" and RemoteUrl !has "registry.yarnpkg.com"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### npm/yarn install lifecycle (postinstall) spawning download or LOLBin tooling

`UC_3453_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe")) AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","certutil.exe","bitsadmin.exe","wscript.exe","cscript.exe","mshta.exe")) AND (Processes.process="*DownloadString*" OR Processes.process="*DownloadFile*" OR Processes.process="*Invoke-WebRequest*" OR Processes.process="*certutil*" OR Processes.process="*bitsadmin*" OR Processes.process="*curl *" OR Processes.process="*wget *" OR Processes.process="*FromBase64String*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","bash.exe","curl.exe","certutil.exe","bitsadmin.exe","wscript.exe","cscript.exe","mshta.exe")
| where ProcessCommandLine has_any ("DownloadString","DownloadFile","Invoke-WebRequest","iwr ","curl ","wget ","certutil","bitsadmin","IEX","Invoke-Expression","-enc ","FromBase64String")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — Why npm lockfiles can be a security blindspot for injecting malicious modules

`UC_3453_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Why npm lockfiles can be a security blindspot for injecting malicious modules ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/world.txt*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Why npm lockfiles can be a security blindspot for injecting malicious modules
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/world.txt"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
