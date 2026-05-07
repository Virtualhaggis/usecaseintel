# [HIGH] Americans sentenced for running 'laptop farms' for North Korea

**Source:** BleepingComputer
**Published:** 2026-05-07
**Article:** https://www.bleepingcomputer.com/news/security/americans-sentenced-for-running-laptop-farms-for-north-korea/

## Threat Profile

Americans sentenced for running 'laptop farms' for North Korea 
By Sergiu Gatlan 
May 7, 2026
09:45 AM
0 


Two U.S. nationals were sentenced to 18 months in prison each for operating so-called laptop farms that helped North Korean IT workers fraudulently obtain remote employment at nearly 70 American companies.


Matthew Isaac Knoot and Erick Ntekereze Prince are the seventh and eighth U.S.-based "laptop farmers" sent to prison since the start of the year as part of a federal initiative tar…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1078** — Valid Accounts
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1199** — Trusted Relationship
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DPRK IT-worker laptop-farm: unauthorised RMM client install on corporate endpoint

`UC_3_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="created" AND (Filesystem.file_name IN ("AnyDesk.exe","rustdesk.exe","RustDesk.exe","TeamViewer.exe","TeamViewer_Service.exe","SRStreamer.exe","chrome_remote_desktop_host.exe","ScreenConnect.ClientService.exe","AnyViewer.exe","JumpDesktop.exe","Splashtop Streamer.exe") OR Filesystem.file_path IN ("*\\AnyDesk\\*","*\\RustDesk\\*","*\\TeamViewer\\*","*\\Splashtop\\*","*\\Chrome Remote Desktop\\*","*\\AnyViewer\\*","*\\JumpDesktop\\*")) AND NOT Filesystem.process_name IN ("IntuneManagementExtension.exe","CcmExec.exe","ccmexec.exe","TrustedInstaller.exe") AND NOT (Filesystem.user="*$" OR Filesystem.user IN ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE")) by host Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | sort - lastTime
```

**Defender KQL:**
```kql
// DPRK laptop-farm: user-context install of remote-desktop / RMM software on a corporate endpoint
let RmmBinaries = dynamic(["AnyDesk.exe","rustdesk.exe","RustDesk.exe","TeamViewer.exe","TeamViewer_Service.exe","Splashtop Streamer.exe","SRStreamer.exe","chrome_remote_desktop_host.exe","ScreenConnect.ClientService.exe","AnyViewer.exe","JumpDesktop.exe"]);
let RmmInstallPaths = dynamic([@"\AnyDesk\", @"\RustDesk\", @"\TeamViewer\", @"\Splashtop\", @"\Chrome Remote Desktop\", @"\AnyViewer\", @"\JumpDesktop\"]);
let CorporateMgmt = dynamic(["IntuneManagementExtension.exe","ccmexec.exe","CcmExec.exe","TrustedInstaller.exe"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName in~ (RmmBinaries) or FolderPath has_any (RmmInstallPaths)
| where InitiatingProcessFileName !in~ (CorporateMgmt)               // exclude legit MDM / SCCM pushes
| where InitiatingProcessAccountName !endswith "$"                    // exclude machine accounts
| where InitiatingProcessAccountSid !in~ ("S-1-5-18","S-1-5-19","S-1-5-20")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessAccountUpn
| order by Timestamp desc
```

### [LLM] DPRK laptop-farm signature: multiple distinct corporate UPNs signing in from a single non-corporate IP

`UC_3_1` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as firstSeen max(_time) as lastSeen dc(Authentication.user) as user_count values(Authentication.user) as users values(Authentication.app) as apps from datamodel=Authentication where Authentication.action="success" AND Authentication.signature_id IN ("Sign-in activity","UserLoggedIn","Interactive") AND NOT (Authentication.src IN ("203.0.113.0/24","198.51.100.0/24")) AND NOT match(Authentication.user,"#EXT#|\$$") by Authentication.src | `drop_dm_object_name(Authentication)` | where user_count >= 2 | eval firstSeen=strftime(firstSeen,"%Y-%m-%d %H:%M:%S"), lastSeen=strftime(lastSeen,"%Y-%m-%d %H:%M:%S") | sort - user_count
```

**Defender KQL:**
```kql
// DPRK laptop-farm signature: ≥2 corporate UPNs sign in interactively from the same non-corporate public IP (30d)
let KnownCorpEgress = dynamic(["203.0.113.0/24","198.51.100.0/24"]);   // <-- replace with corp egress / VPN concentrator CIDRs
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where ErrorCode == 0                                                  // successful auth only
| where IsInteractive == true
| where AccountUpn !contains "#EXT#"                                    // skip B2B guests
| where isnotempty(IPAddress)
| where not(ipv4_is_in_any_range(IPAddress, KnownCorpEgress))
| where not(ipv4_is_private(IPAddress))                                 // residential public IPs only
| summarize FirstSeen   = min(Timestamp),
            LastSeen    = max(Timestamp),
            UserCount   = dcount(AccountUpn),
            Users       = make_set(AccountUpn, 50),
            Apps        = make_set(Application, 25),
            Country     = any(Country),
            City        = any(City),
            ASN         = any(NetworkLocationDetails)
            by IPAddress
| where UserCount >= 2                                                   // 2 = empirical floor; raise to 3+ in tenants with shared home networks
| order by UserCount desc, LastSeen desc
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
