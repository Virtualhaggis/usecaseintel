# [CRIT] 5 Supply Chain Attacks in 48 Hours: Why Securing One Layer Is Not Enough

**Source:** StepSecurity
**Published:** 2026-05-21
**Article:** https://www.stepsecurity.io/blog/5-supply-chain-attacks-in-48-hours-why-securing-one-layer-is-not-enough

## Threat Profile

Back to Blog Threat Intel 5 Supply Chain Attacks in 48 Hours: Why Securing One Layer Is Not Enough A poisoned VS Code extension breached GitHub. A trojanized PyPI package hit Microsoft. Compromised GitHub Actions and a self-spreading npm worm targeted thousands more. In just 48 hours, attackers hit every layer of the software development pipeline. Traditional security tools did not stop any of it. Ashish Kurmi View LinkedIn May 20, 2026
Share on X Share on X Share on LinkedIn Share on Facebook F…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `t.m-kosche.com`
- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `filev2.getsession.org`
- **Domain (defanged):** `api.masscan.cloud`
- **SHA256:** `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`
- **SHA256:** `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74`
- **SHA256:** `e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1`
- **SHA256:** `43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9`
- **SHA256:** `cb86f4f223daa54467c7782a0d8607e9c84e2bb633e6f0e51d9a19579e200990`
- **SHA256:** `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`
- **SHA256:** `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`
- **SHA256:** `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`
- **SHA256:** `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`
- **SHA1:** `558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2`
- **SHA1:** `1c9e803c80cc7fed000022d4c94f4b5bc2e90062`
- **SHA1:** `f0448c62fc57b8a5ce23d8acd6e795cdd76a3b6c`
- **SHA1:** `b9c83f01929e190cda300e76f688bf7ea7e37a7a`
- **SHA1:** `5c267592a87e92c2b005b338bd0d2724c2f64acb`
- **SHA1:** `7f6120bb10c870b9fde146961a18e5bf0b3d4401`
- **SHA1:** `99b7f41bf9e14a2a2c7cc524731336543f552178`

## MITRE ATT&CK Techniques

- **T1071.004** — DNS
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1204.002** — User Execution: Malicious File
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1567.002** — Exfiltration to Cloud Storage
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1547.011** — Boot or Logon Autostart Execution: Plist Modification
- **T1555** — Credentials from Password Stores
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1213.003** — Data from Code Repositories
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Compromised Nx Console VS Code extension (nrwl.angular-console v18.94.0/18.95.0/18.100.0) install on endpoint

`UC_256_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*nrwl.angular-console-18.95.0*","*nrwl.angular-console-18.94.0*","*nrwl.angular-console-18.100.0*") OR Filesystem.file_name IN ("nrwl.angular-console-18.95.0*","nrwl.angular-console-18.94.0*","nrwl.angular-console-18.100.0*")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has_any ("nrwl.angular-console-18.95.0","nrwl.angular-console-18.94.0","nrwl.angular-console-18.100.0")
    or FileName has_any ("nrwl.angular-console-18.95.0","nrwl.angular-console-18.94.0","nrwl.angular-console-18.100.0")
| where InitiatingProcessFileName has_any ("Code","Code Helper","code","code-helper","Code.exe")
    or FolderPath has_any (".vscode/extensions","\\.vscode\\extensions\\")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountUpn, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, SHA1
| order by Timestamp desc
```

### Known Shai-Hulud / Nx Console implant hash match (SHA256/SHA1)

`UC_256_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1","43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9","cb86f4f223daa54467c7782a0d8607e9c84e2bb633e6f0e51d9a19579e200990","069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce","7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8","aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5","558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2","1c9e803c80cc7fed000022d4c94f4b5bc2e90062","f0448c62fc57b8a5ce23d8acd6e795cdd76a3b6c","b9c83f01929e190cda300e76f688bf7ea7e37a7a","5c267592a87e92c2b005b338bd0d2724c2f64acb","7f6120bb10c870b9fde146961a18e5bf0b3d4401","99b7f41bf9e14a2a2c7cc524731336543f552178")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let StealerSHA256 = dynamic(["1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1","43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9","cb86f4f223daa54467c7782a0d8607e9c84e2bb633e6f0e51d9a19579e200990","069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce","7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8","aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5"]);
let StealerSHA1 = dynamic(["558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2","1c9e803c80cc7fed000022d4c94f4b5bc2e90062","f0448c62fc57b8a5ce23d8acd6e795cdd76a3b6c","b9c83f01929e190cda300e76f688bf7ea7e37a7a","5c267592a87e92c2b005b338bd0d2724c2f64acb","7f6120bb10c870b9fde146961a18e5bf0b3d4401","99b7f41bf9e14a2a2c7cc524731336543f552178"]);
union
  (DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (StealerSHA256) or SHA1 in (StealerSHA1) or InitiatingProcessSHA256 in (StealerSHA256) or InitiatingProcessSHA1 in (StealerSHA1)
   | extend Source="DeviceProcessEvents"
   | project Timestamp, DeviceName, AccountUpn, FileName, FolderPath, ProcessCommandLine, SHA256, SHA1, Source),
  (DeviceFileEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (StealerSHA256) or SHA1 in (StealerSHA1)
   | extend Source="DeviceFileEvents"
   | project Timestamp, DeviceName, InitiatingProcessAccountUpn, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, SHA1, Source),
  (DeviceImageLoadEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (StealerSHA256) or SHA1 in (StealerSHA1)
   | extend Source="DeviceImageLoadEvents"
   | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, SHA1, Source)
| order by Timestamp desc
```

### Nx Console / Shai-Hulud C2 connection (t.m-kosche.com, check.git-service.com, filev2.getsession.org, api.masscan.cloud, 83.142.209.194)

`UC_256_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host IN ("t.m-kosche.com","check.git-service.com","filev2.getsession.org","api.masscan.cloud","*.t.m-kosche.com","*.check.git-service.com","*.filev2.getsession.org","*.api.masscan.cloud") OR All_Traffic.dest="83.142.209.194") by All_Traffic.src All_Traffic.src_user All_Traffic.dest_host All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let C2Domains = dynamic(["t.m-kosche.com","check.git-service.com","filev2.getsession.org","api.masscan.cloud"]);
let C2IPs = dynamic(["83.142.209.194"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (isnotempty(RemoteUrl) and (RemoteUrl has_any (C2Domains))) or (RemoteIP in (C2IPs))
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### macOS LaunchAgent/LaunchDaemon plist persistence pointing at Python interpreter

`UC_256_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.process_name) as writer from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*/Library/LaunchAgents/*.plist","*/Library/LaunchDaemons/*.plist") AND Filesystem.process_name IN ("python","python3","node","Code Helper*","Code") by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where DeviceName !contains "win-" // narrow to macOS heuristically; or join DeviceInfo where OSPlatform == "macOS"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/Library/LaunchAgents/","/Library/LaunchDaemons/")
| where FileName endswith ".plist"
| where InitiatingProcessFileName has_any ("Code","Code Helper","node","python","python3","bash","zsh","sh")
     or InitiatingProcessCommandLine has_any ("python","python3","nrwl.angular-console",".vscode/extensions")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform) by DeviceId) on DeviceId
| where OSPlatform == "macOS" or isempty(OSPlatform)
| project Timestamp, DeviceName, OSPlatform, InitiatingProcessAccountUpn, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Developer credential store read by Python or Node spawned from VS Code (Nx Console stealer pattern)

`UC_256_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as files values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*/.ssh/id_rsa","*/.ssh/id_ed25519","*/.ssh/config","*/.aws/credentials","*/.aws/config","*/.config/gh/hosts.yml","*/.npmrc","*/.docker/config.json","*/.kube/config","*/Library/Keychains/login.keychain-db","*/Library/Cookies/Cookies.binarycookies")) AND Filesystem.process_name IN ("python","python3","node") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)` | where mvcount(files) >= 2
```

**Defender KQL:**
```kql
let CredentialPaths = dynamic(["/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa","/.ssh/config","/.ssh/known_hosts","/.aws/credentials","/.aws/config","/.config/gh/hosts.yml","/.config/gh/config.yml","/.npmrc","/.docker/config.json","/.kube/config","/Library/Keychains/login.keychain-db","/Library/Cookies/Cookies.binarycookies","/Library/Application Support/Google/Chrome/Default/Login Data","/Library/Application Support/Google/Chrome/Default/Cookies"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileAccessed","FileOpened")
| where InitiatingProcessFileName in~ ("python","python3","node","osascript")
| where FolderPath has_any (CredentialPaths) or FileName in~ ("id_rsa","id_ed25519","credentials","hosts.yml",".npmrc","login.keychain-db")
| extend ParentIsVSCode = InitiatingProcessParentFileName has_any ("Code","Code Helper","code","code-helper","Code.exe")
| extend FromExtensionDir = InitiatingProcessCommandLine has_any (".vscode/extensions","nrwl.angular-console",".vscode-server/extensions")
| where ParentIsVSCode or FromExtensionDir
| summarize FilesTouched = make_set(strcat(FolderPath, "/", FileName), 50), FileCount = dcount(strcat(FolderPath, "/", FileName)), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SamplePid = any(InitiatingProcessId), SampleCmd = any(InitiatingProcessCommandLine) by DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessParentFileName
| where FileCount >= 2 // distinct credential files reads in same session ≫ single-file dev workflow
| order by FileCount desc
```

### GitHub audit log bulk private-repo clone burst (post Nx Console compromise pattern)

`UC_256_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`github_audit` action IN ("git.clone","repo.download","git.fetch") repo_visibility="private" | bin _time span=1h | stats dc(repo) as RepoCount values(repo) as RepoSample values(actor_ip) as IPs values(user_agent) as UAs min(_time) as firstClone max(_time) as lastClone by actor, _time | where RepoCount >= 25 | eval ratePerMin = round(RepoCount / ((lastClone-firstClone)/60), 2) | sort - RepoCount
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "GitHub"
| where ActionType has_any ("git.clone","repo.download","git.fetch","repo.actions.workflow_run_download_artifact")
| extend RepoName = tostring(parse_json(tostring(RawEventData)).repo)
| extend Visibility = tostring(parse_json(tostring(RawEventData)).visibility)
| where Visibility == "private" or isempty(Visibility) // private OR unknown — err on alert
| summarize RepoCount = dcount(RepoName), RepoSample = make_set(RepoName, 50), FirstClone = min(Timestamp), LastClone = max(Timestamp), IPs = make_set(IPAddress, 10), UAs = make_set(UserAgent, 10) by AccountDisplayName, AccountObjectId, bin(Timestamp, 1h)
| where RepoCount >= 25 // empirical: P99 daily clones per dev is ~10–15; 25 in 1h is anomalous
| extend ClonesPerMinute = round(toreal(RepoCount) / ((LastClone - FirstClone) / 1m), 2)
| order by RepoCount desc
```

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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
  - IP / domain IOC(s): `83.142.209.194`, `t.m-kosche.com`, `check.git-service.com`, `filev2.getsession.org`, `api.masscan.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`, `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74`, `e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1`, `43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9`, `cb86f4f223daa54467c7782a0d8607e9c84e2bb633e6f0e51d9a19579e200990`, `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`, `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5` _(+8 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
