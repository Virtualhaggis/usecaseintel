<!-- curated:true -->
# [HIGH] Dissecting Sapphire Sleet's macOS Intrusion From Lure to Compromise

**Source:** Microsoft Security Blog
**Published:** 2026-04-16
**Article:** https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Microsoft Defender Security Research detailed a **DPRK-linked Sapphire Sleet** macOS intrusion. Sapphire Sleet (a.k.a. BlueNoroff, APT38, Stardust Chollima — DPRK financially-motivated actor) targets **cryptocurrency holders and Web3 employees** with social-engineered macOS lures, abusing **user-driven execution** to bypass Gatekeeper / TCC / XProtect.

Why this matters for non-crypto orgs:
- macOS intrusion playbooks are **publicly maturing** because they work — fewer EDR vendors, less SOC tooling, weaker default execution restrictions than corporate Windows.
- Sapphire Sleet's lure → user-execution → persistence → credential-theft chain is **recipe code** for any DPRK or DPRK-adjacent actor expanding to macOS.
- Most enterprises have macOS exposure (executive laptops, design teams, dev teams) under the radar.

We've upgraded severity to **HIGH** because the **macOS detection backlog is universally underbuilt** in enterprise SOCs — this article is a forcing function for that work.

## Indicators of Compromise

- _Specific Sapphire Sleet macOS sample hashes, lure document filenames, and C2 endpoints should be in the Microsoft research blog body — pull those when writing the IOC snapshot for your tenant._
- The lure pattern: PDF / Zoom-meeting-themed / job-recruitment-themed payload landing as a `.dmg` or `.pkg`, often with a "Verify your identity" social-engineering step.
- Persistence: LaunchAgents / LaunchDaemons + Login Items.
- Post-compromise: keychain dump, browser cookie extraction, crypto-wallet file targeting (Electrum, Exodus, MetaMask LocalStorage, Solana CLI keys).

## MITRE ATT&CK (analyst-validated)

- **T1566.001** — Spearphishing Attachment (themed lures)
- **T1204.002** — User Execution: Malicious File (Gatekeeper bypass via "right-click open" trick)
- **T1543.001** — Create or Modify System Process: Launch Agent (macOS persistence)
- **T1543.004** — Create or Modify System Process: Launch Daemon
- **T1217** — Browser Information Discovery
- **T1555.001** — Credentials from Password Stores: Keychain
- **T1539** — Steal Web Session Cookie
- **T1071.001** — Application Layer Protocol: Web Protocols (HTTPS C2)
- **T1657** — Financial Theft (cryptocurrency)

## Recommended SOC actions (priority-ordered)

1. **Inventory macOS endpoints under EDR coverage.** Most enterprises have ~5-15% of headcount on macOS with weaker tooling. Quantify.
2. **Hunt LaunchAgents / LaunchDaemons created in the last 60 days** — see queries below. This is the single most effective macOS persistence detection.
3. **Hunt for keychain-dump tooling.** `security find-generic-password`, `security dump-keychain`, `chainbreaker`, and unauthorised `Security.framework` library loads.
4. **Audit recent .dmg / .pkg installs** on macOS endpoints, particularly from non-Mac-App-Store sources.
5. **Block Gatekeeper-bypass installer paths** via MDM (Jamf / Intune / Mosyle) if you can — disabling "right-click open" for non-developer users would prevent most user-driven-execution lures.
6. **Block known crypto-wallet-target paths from non-wallet processes** (`~/Library/Application Support/Exodus/`, `~/Library/Application Support/Electrum/`, browser extension storage with wallet IDs).

## Splunk SPL — macOS LaunchAgent / LaunchDaemon creation

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created"
      AND (Filesystem.file_path="*/Library/LaunchAgents/*"
        OR Filesystem.file_path="*/Library/LaunchDaemons/*"
        OR Filesystem.file_path="*/Library/StartupItems/*")
      AND Filesystem.file_name="*.plist"
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path,
       Filesystem.file_name, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

## Splunk SPL — macOS Gatekeeper / quarantine-attribute removal

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.os="macos"
      AND (Processes.process="*xattr*-d*com.apple.quarantine*"
        OR Processes.process="*spctl --master-disable*"
        OR Processes.process="*spctl -a -t*-vv*"
        OR Processes.process="*csrutil disable*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — keychain dump / extraction

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name="security"
      AND (Processes.process="*dump-keychain*"
        OR Processes.process="*find-generic-password*"
        OR Processes.process="*find-internet-password*"
        OR Processes.process="*unlock-keychain*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — crypto-wallet path access from non-wallet processes

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*/Library/Application Support/Exodus/*"
        OR Filesystem.file_path="*/Library/Application Support/Electrum/*"
        OR Filesystem.file_path="*/Library/Application Support/Bitcoin/*"
        OR Filesystem.file_path="*/.metamask/*"
        OR Filesystem.file_path="*/.config/solana/*"
        OR Filesystem.file_path="*Wallet*")
      AND Filesystem.action="read"
      AND NOT Filesystem.process_name IN ("Exodus","Electrum","Atomic","MetaMask","bitcoin-qt")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
```

## Defender KQL — macOS persistence (LaunchAgent / LaunchDaemon)

```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where DeviceName has "Mac" or InitiatingProcessVersionInfoProductName has "macOS"
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("/Library/LaunchAgents/","/Library/LaunchDaemons/",
                              "/Library/StartupItems/")
| where FileName endswith ".plist"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — macOS quarantine attribute removal

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where ProcessCommandLine has_any (
    "xattr -d com.apple.quarantine",
    "xattr -dr com.apple.quarantine",
    "spctl --master-disable",
    "csrutil disable")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — keychain dump attempts

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName == "security"
| where ProcessCommandLine has_any (
    "dump-keychain","find-generic-password","find-internet-password","unlock-keychain")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — DMG / PKG execution post-download

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".dmg" or FileName endswith ".pkg"
| where ActionType == "FileCreated"
| where FolderPath has "/Downloads/" or FolderPath has "/Desktop/"
| join kind=inner (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("installer","hdiutil","open")
    | project Timestamp, DeviceName, ProcessCommandLine, ParentName=InitiatingProcessFileName) on DeviceName
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

macOS detection logic in most enterprise SOCs is **5-7 years behind Windows** — this is documented across the industry. Sapphire Sleet (and Famous Chollima, BlueNoroff, ContagiousInterview, etc.) is operating in that detection gap on purpose, and the gap will widen if you don't actively close it. The **single highest-leverage macOS detection** is LaunchAgent/LaunchDaemon plist creation — it catches Sapphire Sleet, Lazarus Group, KandyKorn, RustBucket, ObjCShellz, and most other macOS persistence in one rule. If you have *no* macOS detections live today, that's the one to build first.
