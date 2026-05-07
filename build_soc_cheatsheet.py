"""Build cheatsheet.html — a self-contained SOC analyst cheat sheet.

For each Microsoft 365 Defender Advanced Hunting table we ship a
curated set of high-utility queries an analyst would actually run
during a shift: discovery, hunting, investigation, anomaly.

Re-run any time:
    python build_soc_cheatsheet.py
"""
from __future__ import annotations

import html
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "cheatsheet.html"
SCHEMA = json.loads((ROOT / "data_sources" / "defender_spec_tables.json").read_text(encoding="utf-8"))
SENTINEL_SCHEMA = json.loads((ROOT / "data_sources" / "sentinel_spec_tables.json").read_text(encoding="utf-8"))


# =============================================================================
# Per-table query bundles
# =============================================================================
# Each entry: {table: [(title, description, kql), ...], ...}
# KQL is verbatim Defender Advanced Hunting style — schema-correct, time-bound,
# machine-account-filtered where applicable, BluRaven house style.

QUERIES: dict[str, list[tuple[str, str, str]]] = {

    "DeviceProcessEvents": [
        ("Recent processes on a device",
         "Quick triage: every process spawned on a host in the last hour. Replace `<DeviceName>`.",
         '''DeviceProcessEvents
| where Timestamp > ago(1h)
| where DeviceName =~ "<DeviceName>"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc'''),

        ("Processes spawned by a user in the last 24h",
         "User-scoped activity. Replace `<UserName>`.",
         '''DeviceProcessEvents
| where Timestamp > ago(24h)
| where AccountName =~ "<UserName>"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc'''),

        ("LOLBin executions (living-off-the-land binaries)",
         "Built-in binaries adversaries abuse — high-signal when paired with unusual parents/cmdlines.",
         '''DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe",
                      "rundll32.exe","wmic.exe","msbuild.exe","installutil.exe",
                      "wscript.exe","cscript.exe","cmstp.exe","forfiles.exe")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc'''),

        ("Office app spawning a script host",
         "Classic macro-payload signal — Word/Excel/Outlook spawning powershell/cmd/wscript.",
         '''DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe",
                                         "outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe",
                       "mshta.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine
| order by Timestamp desc'''),

        ("PowerShell with `-EncodedCommand` (decode inline)",
         "Decodes the base64 payload right in the result so analysts can read it.",
         '''DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-EncodedCommand","-enc ","-EC ")
| extend B64 = extract(@"(?i)(?:-(?:e(?:nc(?:odedcommand)?)?))\\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(B64)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, Decoded
| order by Timestamp desc'''),

        ("Suspicious PowerShell flags",
         "Hidden window, no-profile, bypass-policy — common evasion combos.",
         '''DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)-w(in)?(dow)?style?\\s+h(idden)?|-nop(rofile)?|-ep\\s+bypass|frombase64string|invoke-expression|iex\\s*\\(|net\\.webclient"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc'''),

        ("Rare child by parent (anti-baseline, 30d)",
         "Anti-baseline join. A child binary spawned by a parent that has never spawned it during the 30d baseline.",
         '''let BaselineDays = 30d;
let RecentHours = 4h;
let Baseline = DeviceProcessEvents
    | where Timestamp between (ago(BaselineDays) .. ago(RecentHours))
    | summarize by InitiatingProcessFileName, FileName;
DeviceProcessEvents
| where Timestamp > ago(RecentHours)
| where AccountName !endswith "$"
| where FileName !in~ ("conhost.exe","svchost.exe","backgroundtaskhost.exe",
                       "wermgr.exe","wuauclt.exe","searchindexer.exe")
| join kind=leftanti Baseline on InitiatingProcessFileName, FileName
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, Child = FileName,
          ChildCmd = ProcessCommandLine
| order by Timestamp desc'''),

        ("Files run from temp / AppData",
         "Most user-mode malware drops to %TEMP% or %APPDATA% before execution.",
         '''DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FolderPath has_any (@"\\AppData\\Local\\Temp\\", @"\\AppData\\Roaming\\",
                             @"\\Windows\\Temp\\", @"\\Users\\Public\\")
| where FileName endswith ".exe" or FileName endswith ".dll"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc'''),

        ("Process count timechart",
         "Sudden volume spikes — beaconing or compromise-driven hyperactivity.",
         '''DeviceProcessEvents
| where Timestamp > ago(7d)
| summarize ProcessCount = count() by bin(Timestamp, 1h), DeviceName
| render timechart with (ytitle="Processes per hour")'''),

        ("Hash IOC sweep",
         "Replace the dynamic list with article-specific hashes.",
         '''let BadHashes = dynamic(["<sha256-1>","<sha256-2>"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ (BadHashes)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA256
| order by Timestamp desc'''),
    ],

    "DeviceNetworkEvents": [
        ("Recent outbound from a device",
         "First-look network telemetry. Replace `<DeviceName>`.",
         '''DeviceNetworkEvents
| where Timestamp > ago(1h)
| where DeviceName =~ "<DeviceName>"
| where ActionType == "ConnectionSuccess"
| project Timestamp, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc'''),

        ("Public-IP egress only",
         "Strip out internal-LAN noise — focuses on internet-bound traffic.",
         '''DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc'''),

        ("LOLBin reaching the internet",
         "LOLBin + public destination = high signal. LOLBin alone is noise.",
         '''DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe","rundll32.exe",
    "msbuild.exe","installutil.exe","wmic.exe","wscript.exe","cscript.exe",
    "cmstp.exe","forfiles.exe","ftp.exe","tftp.exe","odbcconf.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc'''),

        ("Beaconing detector — periodic outbound",
         "Sustained, periodic connections to one destination from one process — C2 signature.",
         '''DeviceNetworkEvents
| where Timestamp > ago(2h)
| where RemoteIPType == "Public"
| summarize ConnCount = count(),
            DistinctMinutes = dcount(bin(Timestamp, 1m))
            by DeviceId, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where ConnCount > 50 and DistinctMinutes > 30   // sustained, not bursty
| order by ConnCount desc'''),

        ("Connections by IP block-list",
         "Bring your own IOC list.",
         '''let BadIPs = dynamic(["1.2.3.4","5.6.7.8"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemoteIP in (BadIPs)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc'''),

        ("Rare destination (org-wide first-seen)",
         "Domain seen for the first time across the org in the last hour.",
         '''let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1h))
    | summarize BaselineHosts = dcount(DeviceName) by RemoteUrl
    | where BaselineHosts > 2;
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where isnotempty(RemoteUrl)
| join kind=leftanti Baseline on RemoteUrl
| summarize FirstSeen = min(Timestamp), HostsCount = dcount(DeviceName)
            by RemoteUrl
| order by FirstSeen desc'''),

        ("Top destinations by data volume",
         "If your tenant tracks byte counts. Useful for exfil triage.",
         '''DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| summarize TotalConnections = count(),
            UniqueDevices    = dcount(DeviceName)
            by RemoteUrl, RemoteIP
| order by TotalConnections desc
| take 50'''),

        ("Listening services on a device",
         "Server-side foothold detection. Replace `<DeviceName>`.",
         '''DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>"
| where ActionType == "ListeningConnectionCreated"
| project Timestamp, LocalIP, LocalPort, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc'''),
    ],

    "DeviceFileEvents": [
        ("Recent file creates in suspect paths",
         "Most user-mode malware drops to temp/AppData; this is the first-look query.",
         '''DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\\AppData\\Local\\Temp\\", @"\\AppData\\Roaming\\",
                             @"\\Windows\\Temp\\", @"\\Users\\Public\\")
| where FileName endswith ".exe" or FileName endswith ".dll"
   or FileName endswith ".ps1" or FileName endswith ".bat"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc'''),

        ("Hash IOC match across files",
         "Sweep file telemetry for known-bad hashes.",
         '''let BadHashes = dynamic(["<sha256-1>","<sha256-2>"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 in~ (BadHashes) or SHA1 in~ (BadHashes) or MD5 in~ (BadHashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc'''),

        ("Mass file rename (ransomware)",
         "200+ unique-file renames in a 1-min window from one process — encryption-stage signal.",
         '''DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName)
            by DeviceName, InitiatingProcessAccountName,
               InitiatingProcessFileName, bin(Timestamp, 1m)
| where files > 200
| order by files desc'''),

        ("Browser cookie / login DB access by non-browser",
         "Infostealer (RedLine, Lumma, Vidar) reading Login Data / cookies.",
         '''DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\\Google\\Chrome\\User Data\\",
                             @"\\Microsoft\\Edge\\User Data\\",
                             @"\\Mozilla\\Firefox\\Profiles\\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe",
                                          "brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, FolderPath, FileName, ActionType
| order by Timestamp desc'''),

        ("Crypto-wallet keystore access by non-wallet process",
         "MetaMask / Exodus / Bitcoin / Phantom keystore touched by something unexpected.",
         '''DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\\Ethereum\\keystore\\", @"\\Bitcoin\\",
                             @"\\Exodus\\", @"\\Electrum\\wallets\\",
                             @"\\MetaMask\\", @"\\Phantom\\",
                             @"\\Atomic\\Local Storage\\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe",
                                          "electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, FolderPath, FileName, ActionType
| order by Timestamp desc'''),

        ("Files dropped under a specific user",
         "User-scoped drop hunt. Replace `<UserName>`.",
         '''DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName =~ "<UserName>"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc'''),
    ],

    "DeviceLogonEvents": [
        ("Failed logons in last 24h",
         "Brute-force / credential-spray triage.",
         '''DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| where AccountName !endswith "$"
| summarize FailCount = count(),
            DistinctTargets = dcount(DeviceName),
            FirstAttempt = min(Timestamp),
            LastAttempt = max(Timestamp)
            by AccountName, RemoteIP, FailureReason
| where FailCount > 5
| order by FailCount desc'''),

        ("Successful RDP from public IP",
         "RemoteInteractive (LogonType 10) from a public source — high-priority review.",
         '''DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where RemoteIPType == "Public"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteDeviceName,
          IsLocalAdmin, Protocol
| order by Timestamp desc'''),

        ("NTLM where Kerberos is expected",
         "NTLM-over-RDP or NTLM-from-domain-joined-host = pivot signal for cred theft.",
         '''DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where Protocol == "NTLM"
| where LogonType in ("RemoteInteractive","Network")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType,
          IsLocalAdmin, RemoteDeviceName
| order by Timestamp desc'''),

        ("Local-admin interactive logons",
         "Privilege use — every hit deserves review on production hosts.",
         '''DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where IsLocalAdmin == true
| where LogonType in ("Interactive","RemoteInteractive")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, Protocol
| order by Timestamp desc'''),

        ("After-hours interactive logon",
         "Tune the hour bounds for your business. Default: 21:00–06:00 local.",
         '''DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType == "Interactive"
| where AccountName !endswith "$"
| extend Hour = datetime_part("hour", Timestamp)
| where Hour >= 21 or Hour < 6
| project Timestamp, Hour, DeviceName, AccountName, RemoteIP, IsLocalAdmin
| order by Timestamp desc'''),

        ("Logon-velocity anomaly per account",
         "Account logging on to >5 distinct hosts in 1h — lateral-movement candidate.",
         '''DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where AccountName !endswith "$"
| summarize HostsCount = dcount(DeviceName)
            by AccountName, bin(Timestamp, 1h)
| where HostsCount > 5
| order by HostsCount desc'''),
    ],

    "DeviceImageLoadEvents": [
        ("DLLs loaded by lsass.exe outside System32",
         "Credential-theft tooling loads custom DLLs into LSASS. Drop System32-resident loads.",
         '''DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "lsass.exe"
| where FolderPath !startswith @"C:\\Windows\\"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256
| order by Timestamp desc'''),

        ("Side-loaded DLLs adjacent to dropped binary",
         "DLL search-order hijack. The loaded module sits next to a binary that isn't its expected loader.",
         '''DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has_any (@"\\AppData\\Local\\Temp\\",
                                              @"\\AppData\\Roaming\\",
                                              @"\\Windows\\Temp\\")
| where FolderPath =~ InitiatingProcessFolderPath
   and SHA256 != InitiatingProcessSHA256
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA256
| order by Timestamp desc'''),

        ("Loads of a specific suspicious DLL",
         "Replace `<dll-name>` with the IOC.",
         '''DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName =~ "<dll-name>"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc'''),

        ("Volume of image loads per device (anomaly)",
         "Sudden surge in DLL loads = injection or unpacking activity.",
         '''DeviceImageLoadEvents
| where Timestamp > ago(7d)
| summarize Loads = count() by DeviceName, bin(Timestamp, 1h)
| render timechart with (ytitle="DLL loads per hour")'''),
    ],

    "DeviceRegistryEvents": [
        ("Run / RunOnce key changes",
         "Classic persistence locations (HKLM + HKCU).",
         '''DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\\Run", @"\\RunOnce")
| where InitiatingProcessFileName !in~ ("msiexec.exe","explorer.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey,
          RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc'''),

        ("Image File Execution Options (debugger hijack)",
         "Setting `Debugger` under IFEO redirects a binary's launch — common evasion.",
         '''DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"\\Image File Execution Options\\"
| where RegistryValueName =~ "Debugger"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
          InitiatingProcessFileName
| order by Timestamp desc'''),

        ("Service installation",
         "New Windows service registration — pair with `sc.exe` cmdline check.",
         '''DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType == "RegistryKeyCreated"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\"
| project Timestamp, DeviceName, RegistryKey, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc'''),

        ("Browser extension installs",
         "Watch the extension policy keys.",
         '''DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any (@"\\Software\\Google\\Chrome\\Extensions\\",
                              @"\\Software\\Microsoft\\Edge\\Extensions\\",
                              @"\\Software\\Mozilla\\Firefox\\Extensions\\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
          RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc'''),
    ],

    "DeviceEvents": [
        ("AMSI scan results — flagged content",
         "AMSI providers scan in-memory script payloads; non-clean ScanResult is high-signal.",
         '''DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AmsiScanResult"
| extend Result = tostring(parse_json(AdditionalFields).ScanResult),
         Content = tostring(parse_json(AdditionalFields).ContentName)
| where Result != "Clean"
| project Timestamp, DeviceName, InitiatingProcessFileName, Content, Result
| order by Timestamp desc'''),

        ("DNS queries to suspect TLDs",
         "TLD-based heuristic.",
         '''DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend Q = tostring(parse_json(AdditionalFields).QueryName)
| where Q endswith ".onion" or Q endswith ".ru" or Q endswith ".su" or Q endswith ".cn"
| project Timestamp, DeviceName, Q, InitiatingProcessFileName
| order by Timestamp desc'''),

        ("LSASS process access (credential dumping)",
         "Anything opening LSASS that isn't a Microsoft signed component is suspect.",
         '''DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc'''),

        ("USB drive insertion / new external storage",
         "Data-loss-prevention hunt.",
         '''DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("UsbDriveMount","UsbDriveDriveLetterChanged")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          AdditionalFields
| order by Timestamp desc'''),

        ("PowerShell ScriptBlock log — suspicious content",
         "Defender records ScriptBlock content for risky payloads.",
         '''DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "PowerShellCommand"
| extend Cmd = tostring(parse_json(AdditionalFields).Command)
| where Cmd matches regex @"(?i)downloadstring|frombase64string|invoke-expression|new-object\\s+net\\.webclient"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessCommandLine, Cmd
| order by Timestamp desc'''),
    ],

    "DeviceInfo": [
        ("Inventory: OS distribution",
         "Snapshot of OS spread.",
         '''DeviceInfo
| where Timestamp > ago(1d)
| summarize Devices = dcount(DeviceName) by OSPlatform, OSVersion
| order by Devices desc'''),

        ("Internet-facing devices",
         "Pivot for prioritising vulnerability triage.",
         '''DeviceInfo
| where Timestamp > ago(1d)
| where IsInternetFacing == true
| project DeviceName, OSPlatform, OSVersion, PublicIP, MachineGroup'''),

        ("Find a device by partial name",
         "Replace `<substring>`.",
         '''DeviceInfo
| where Timestamp > ago(1d)
| where DeviceName has "<substring>"
| project DeviceName, OSPlatform, OSVersion, MachineGroup, JoinType, IsAzureADJoined'''),

        ("Build dynamic device set for filtering",
         "Use this snippet to scope another query to (e.g.) only Win10 hosts.",
         '''let win10 = DeviceInfo
    | where Timestamp > ago(1d)
    | where OSPlatform == "Windows10"
    | summarize make_set(DeviceName);
DeviceProcessEvents
| where DeviceName in (win10)
| where FileName =~ "<binary>"'''),
    ],

    "DeviceNetworkInfo": [
        ("Recent IP changes per device",
         "Useful for tracking dynamic-IP movement of a target host.",
         '''DeviceNetworkInfo
| where Timestamp > ago(7d)
| mv-expand IP = parse_json(IPAddresses)
| project Timestamp, DeviceName, NetworkAdapterName, IP = tostring(IP.IPAddress)
| order by Timestamp desc'''),

        ("VPN-tunnel adapters",
         "Adapters indicating tunnel software in play.",
         '''DeviceNetworkInfo
| where Timestamp > ago(1d)
| where TunnelType !in ("None","")
| project DeviceName, NetworkAdapterName, TunnelType, NetworkAdapterStatus'''),
    ],

    "EmailEvents": [
        ("Inbound mail to a recipient",
         "Replace `<user@domain>` to triage one user's mailbox traffic.",
         '''EmailEvents
| where Timestamp > ago(24h)
| where EmailDirection == "Inbound"
| where RecipientEmailAddress =~ "<user@domain>"
| project Timestamp, SenderFromAddress, Subject, DeliveryAction,
          DeliveryLocation, NetworkMessageId
| order by Timestamp desc'''),

        ("Phish blocked vs delivered for a sender",
         "Sender-level triage. Replace `<sender@domain>`.",
         '''EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "<sender@domain>"
| summarize Count = count() by DeliveryAction, EmailDirection
| order by Count desc'''),

        ("Senders with high recipient fan-out",
         "Mass-mail / spam-spike pattern.",
         '''EmailEvents
| where Timestamp > ago(24h)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| summarize Recipients = dcount(RecipientEmailAddress)
            by SenderFromAddress, SenderFromDomain
| where Recipients > 25                      // threshold tuneable
| order by Recipients desc'''),

        ("Authentication-fail mail (SPF/DKIM/DMARC)",
         "Spoofed envelope vs header. Inspect the AuthenticationDetails JSON.",
         '''EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where AuthenticationDetails has_any ("SPF=fail","DKIM=fail","DMARC=fail")
| project Timestamp, SenderMailFromAddress, SenderFromAddress,
          RecipientEmailAddress, Subject, AuthenticationDetails
| order by Timestamp desc'''),

        ("Phish + URL + click — full chain",
         "Joins the three phishing tables for end-to-end correlation.",
         '''EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| join kind=inner (
    EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
  ) on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | project NetworkMessageId, ClickTime = Timestamp, AccountUpn
  ) on NetworkMessageId
| project Timestamp, ClickTime, SenderFromAddress, RecipientEmailAddress,
          Subject, Url, UrlDomain, AccountUpn'''),
    ],

    "EmailUrlInfo": [
        ("URLs in mail to a recipient",
         "Useful for retro phish-URL retrieval. Replace `<user@domain>`.",
         '''EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress =~ "<user@domain>"
| join kind=inner (
    EmailUrlInfo | project NetworkMessageId, Url, UrlDomain, UrlLocation
  ) on NetworkMessageId
| project Timestamp, SenderFromAddress, Subject, Url, UrlDomain, UrlLocation
| order by Timestamp desc'''),

        ("All URLs from a specific domain in inbound mail",
         "Replace `<bad-domain.com>`.",
         '''EmailUrlInfo
| where Timestamp > ago(30d)
| where UrlDomain =~ "<bad-domain.com>"
| project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation
| order by Timestamp desc'''),
    ],

    "EmailAttachmentInfo": [
        ("Malicious attachments delivered to mailbox",
         "Defender-verdicted Malware that still landed in user inbox = high-priority remediation.",
         '''EmailAttachmentInfo
| where Timestamp > ago(7d)
| where MalwareFilterVerdict == "Malware"
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          FileName, FileType, FileSize, SHA256, ThreatNames
| order by Timestamp desc'''),

        ("Specific file-type attachments",
         "Hunt for risky attachment types — ISO, IMG, ZIP, HTML.",
         '''EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in~ ("ISO","IMG","ZIP","RAR","HTML","HTM","DOCM","XLSM")
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          FileName, FileType, FileSize, SHA256
| order by Timestamp desc'''),

        ("Attachment SHA256 sweep across endpoints",
         "Match attachment hashes against endpoint file-write telemetry.",
         '''let MalHashes = EmailAttachmentInfo
    | where Timestamp > ago(7d)
    | where MalwareFilterVerdict == "Malware"
    | summarize make_set(SHA256);
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 in (MalHashes)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName'''),
    ],

    "EmailPostDeliveryEvents": [
        ("ZAP (Zero-hour Auto Purge) actions",
         "Defender retroactively yanked a delivered message.",
         '''EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType == "ZAP"
| project Timestamp, NetworkMessageId, Action, ActionTrigger,
          ActionResult, DeliveryLocation, RecipientEmailAddress
| order by Timestamp desc'''),

        ("User-initiated message deletes",
         "Sometimes a user reports phish themselves; this surfaces those signals.",
         '''EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionTrigger == "User"
| where Action in ("Delete","MoveToJunk")
| project Timestamp, NetworkMessageId, Action, RecipientEmailAddress
| order by Timestamp desc'''),
    ],

    "UrlClickEvents": [
        ("All Safe-Links click-throughs (user bypass)",
         "Inherently rare and high-fidelity — Safe Links warned and the user proceeded.",
         '''UrlClickEvents
| where Timestamp > ago(30d)
| where ActionType == "ClickedThrough"
| project Timestamp, AccountUpn, IPAddress, Url, Workload, NetworkMessageId
| order by Timestamp desc'''),

        ("Clicks on a domain pattern",
         "Hunt clicks on a brand-impersonation pattern.",
         '''UrlClickEvents
| where Timestamp > ago(30d)
| where Url has "<suspect-domain-pattern>"
| project Timestamp, AccountUpn, IPAddress, Url, ActionType, Workload, NetworkMessageId
| order by Timestamp desc'''),

        ("Clicks on URLs not from email (Teams / Office)",
         "Clicks delivered via Teams chat or Office docs, not just mail.",
         '''UrlClickEvents
| where Timestamp > ago(7d)
| where Workload != "Email"
| project Timestamp, AccountUpn, IPAddress, Url, Workload, ActionType
| order by Timestamp desc'''),
    ],

    "IdentityLogonEvents": [
        ("Failed Kerberos auth (T1110 brute-force)",
         "Repeated failures from one source = spray candidate.",
         '''IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| where Protocol == "Kerberos"
| where AccountName !endswith "$"
| summarize FailCount = count(),
            Targets = dcount(AccountUpn)
            by IPAddress, FailureReason
| where FailCount > 10
| order by FailCount desc'''),

        ("NTLM where Kerberos is expected",
         "NTLM RemoteInteractive on a domain-joined estate is unusual and worth review.",
         '''IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where Protocol == "NTLM" and LogonType == "RemoteInteractive"
| where AccountName !endswith "$"
| project Timestamp, AccountUpn, DeviceName, IPAddress, LogonType, Protocol
| order by Timestamp desc'''),

        ("Service-account interactive logons",
         "Service accounts shouldn't sit at a console. Tune the prefix list.",
         '''IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive","RemoteInteractive")
| where AccountName startswith "svc-" or AccountName startswith "sa-"
| project Timestamp, AccountUpn, DeviceName, IPAddress, LogonType
| order by Timestamp desc'''),
    ],

    "IdentityQueryEvents": [
        ("BloodHound-style enumeration",
         "All-users LDAP query — recon tooling signature.",
         '''IdentityQueryEvents
| where Timestamp > ago(7d)
| where ActionType == "LDAPQuery"
| where Query has "(samAccountType=805306368)"        // user objects
| summarize Count = count() by AccountName, IPAddress, DeviceName
| where Count > 1
| order by Count desc'''),

        ("Kerberoasting recon — SPN enumeration",
         "Querying for accounts with servicePrincipalName.",
         '''IdentityQueryEvents
| where Timestamp > ago(7d)
| where ActionType == "LDAPQuery"
| where Query has "servicePrincipalName"
| project Timestamp, AccountName, DeviceName, IPAddress, Query
| order by Timestamp desc'''),

        ("LDAP query volume per source",
         "Outlier-volume detection.",
         '''IdentityQueryEvents
| where Timestamp > ago(24h)
| where ActionType == "LDAPQuery"
| summarize Queries = count() by AccountName, DeviceName, IPAddress, bin(Timestamp, 1h)
| where Queries > 200
| order by Queries desc'''),
    ],

    "IdentityDirectoryEvents": [
        ("Privileged-group membership changes",
         "Adds to Domain Admins / Enterprise Admins / DnsAdmins are crown-jewel events.",
         '''IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Group Membership changed"
| where AdditionalFields has_any ("Domain Admins","Enterprise Admins","DnsAdmins",
                                    "Schema Admins","Account Operators")
| project Timestamp, ActionType, AccountUpn,
          TargetAccountUpn, AdditionalFields
| order by Timestamp desc'''),

        ("Forced password resets",
         "Common pre-impersonation step.",
         '''IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Forced password reset"
| project Timestamp, AccountUpn, TargetAccountUpn,
          DestinationDeviceName, DestinationIPAddress
| order by Timestamp desc'''),

        ("New account creation from non-admin source",
         "Account creation outside helpdesk / IT-admin endpoints.",
         '''IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Account created"
| project Timestamp, AccountUpn, TargetAccountUpn,
          DestinationDeviceName, DestinationIPAddress, AdditionalFields
| order by Timestamp desc'''),
    ],

    "IdentityInfo": [
        ("Disabled accounts that have signed in recently",
         "A disabled account producing sign-in events is a major red flag.",
         '''AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| join kind=inner (
    IdentityInfo | project AccountUpn, IsAccountEnabled, JobTitle, Department
  ) on AccountUpn
| where IsAccountEnabled == false
| project Timestamp, AccountUpn, JobTitle, Department, IPAddress, Application
| order by Timestamp desc'''),

        ("Privileged-role members",
         "Enrich with role title / department for triage.",
         '''IdentityInfo
| where Timestamp > ago(1d)
| where JobTitle has_any ("CEO","CFO","CISO","CIO","Director","VP","Admin")
| project AccountUpn, JobTitle, Department, City, Country, IsAccountEnabled'''),
    ],

    "AADSignInEventsBeta": [
        ("Failed sign-ins by user",
         "Replace `<user@domain>`.",
         '''AADSignInEventsBeta
| where Timestamp > ago(24h)
| where AccountUpn =~ "<user@domain>"
| where ErrorCode != 0
| project Timestamp, IPAddress, Country, Application, ErrorCode, RiskLevelDuringSignIn
| order by Timestamp desc'''),

        ("Impossible travel",
         "Two successful sign-ins from different countries within 60 minutes.",
         '''let WindowMinutes = 60;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where isnotempty(Country)
| project Timestamp, AccountUpn, Country, City, IPAddress, Application
| order by AccountUpn asc, Timestamp asc
| extend PrevCountry = prev(Country),
         PrevCity    = prev(City),
         PrevTime    = prev(Timestamp),
         PrevAccount = prev(AccountUpn)
| where AccountUpn == PrevAccount
   and Country != PrevCountry
   and datetime_diff('minute', Timestamp, PrevTime) <= WindowMinutes
| project AccountUpn,
          From = PrevCountry, FromTime = PrevTime,
          To = Country, ToTime = Timestamp,
          MinutesDelta = datetime_diff('minute', Timestamp, PrevTime),
          IPAddress, Application
| order by ToTime desc'''),

        ("Legacy auth still in use",
         "`Other clients` = legacy protocols (POP/IMAP/SMTP basic). Should be zero in modern tenants.",
         '''AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ClientAppUsed == "Other clients"
| where ErrorCode == 0
| summarize Sessions = count() by AccountUpn, IPAddress, Application
| order by Sessions desc'''),

        ("Sign-ins from anonymous proxy / Tor",
         "IsAnonymousProxy is M365D's tag.",
         '''AADSignInEventsBeta
| where Timestamp > ago(7d)
| where IsAnonymousProxy == true
| project Timestamp, AccountUpn, IPAddress, Country, Application,
          ErrorCode, RiskLevelDuringSignIn
| order by Timestamp desc'''),

        ("MFA Challenge failed (push fatigue)",
         "Repeated MFA challenges to the same user from the same IP — push-bombing.",
         '''AADSignInEventsBeta
| where Timestamp > ago(24h)
| where ErrorCode == 50158                    // MFA Challenge required / failed
| summarize Attempts = count() by AccountUpn, IPAddress, bin(Timestamp, 5m)
| where Attempts > 3
| order by Attempts desc'''),

        ("New AAD application — first-seen org-wide",
         "First sign-in to an AAD app the tenant has never touched before — illicit-consent risk.",
         '''AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where Application !in~ ("Microsoft Authenticator","Office 365","Microsoft Office",
                            "Microsoft Teams","Microsoft Edge","Outlook")
| where ResourceId == "00000003-0000-0000-c000-000000000000"   // Microsoft Graph
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            UserCount = dcount(AccountUpn)
            by Application, ApplicationId
| where FirstSeen > ago(2h)
| order by FirstSeen desc'''),
    ],

    "AlertInfo": [
        ("New alert titles last 24h",
         "Detection-rule volume / variety.",
         '''AlertInfo
| where Timestamp > ago(24h)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Count = count()
            by Title, Category, Severity
| order by Count desc'''),

        ("High / critical alerts only",
         "Severity-scoped triage feed.",
         '''AlertInfo
| where Timestamp > ago(7d)
| where Severity in ("High","Medium")
| project Timestamp, AlertId, Title, Category, Severity, ServiceSource, DetectionSource
| order by Timestamp desc'''),

        ("Top MITRE techniques observed",
         "Unique-technique frequency.",
         '''AlertInfo
| where Timestamp > ago(7d)
| mv-expand todynamic(AttackTechniques)
| extend Technique = tostring(AttackTechniques)
| summarize Count = count() by Technique
| order by Count desc'''),
    ],

    "AlertEvidence": [
        ("Per-alert entity summary",
         "BluRaven course's alert-context query — answers the analyst's first questions.",
         '''AlertEvidence
| where Timestamp > ago(7d)
| join kind=inner AlertInfo on AlertId
| summarize Count = count(),
            FirstTriggered = min(Timestamp),
            LastTriggered  = max(Timestamp),
            DeviceCount    = dcountif(DeviceName, EntityType == "Machine"),
            Devices        = make_set_if(DeviceName, EntityType == "Machine", 50),
            UserCount      = dcountif(AccountUpn, EntityType == "User"),
            Users          = make_set_if(AccountUpn, EntityType == "User", 50),
            Files          = make_set_if(FileName, EntityType == "File", 50),
            IPs            = make_set_if(RemoteIP, EntityType == "Ip", 50)
            by Title, Severity, Category
| order by Count desc'''),

        ("Alerts on a specific device",
         "Pivot to one machine.",
         '''AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>"
| join kind=inner AlertInfo on AlertId
| project Timestamp, Title, Severity, EntityType, EvidenceRole,
          FileName, RemoteUrl, AccountName
| order by Timestamp desc'''),

        ("All file IOCs across active alerts",
         "Pivot for sweep against `DeviceFileEvents`.",
         '''AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "File" and isnotempty(SHA256)
| summarize Alerts = dcount(AlertId), FirstSeen = min(Timestamp)
            by FileName, SHA256
| order by Alerts desc'''),
    ],

    "CloudAppEvents": [
        ("New external-domain user activity in OneDrive",
         "External-collaboration risk.",
         '''CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft OneDrive for Business"
| where AccountDisplayName !endswith "@yourdomain.com"
| project Timestamp, ActionType, AccountDisplayName, ObjectName, IPAddress, CountryCode'''),

        ("Admin actions from anonymous proxy",
         "Admin operation + anonymous source = compromise red-flag.",
         '''CloudAppEvents
| where Timestamp > ago(7d)
| where IsAdminOperation == true
| where IsAnonymousProxy == true
| project Timestamp, AccountDisplayName, ActionType, Application,
          IPAddress, CountryCode, UserAgent'''),

        ("Newly authorised SaaS app",
         "First-seen application in tenant audit.",
         '''CloudAppEvents
| where Timestamp > ago(7d)
| summarize FirstSeen = min(Timestamp), Activities = count(),
            Users = dcount(AccountObjectId)
            by Application, ApplicationId
| where FirstSeen > ago(1d)
| order by Activities desc'''),
    ],

    "DeviceTvmSoftwareInventory": [
        ("Outdated browsers on production hosts",
         "Tune `<min-version>` to your target threshold.",
         '''DeviceTvmSoftwareInventory
| where Timestamp > ago(1d)
| where SoftwareName has_any ("chrome","msedge","firefox")
| where SoftwareVersion < "<min-version>"
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion'''),

        ("End-of-support OSes",
         "Where you're knowingly running risk.",
         '''DeviceTvmSoftwareInventory
| where Timestamp > ago(1d)
| where EndOfSupportStatus != "Supported"
| project DeviceName, OSPlatform, OSVersion, SoftwareName,
          SoftwareVersion, EndOfSupportStatus, EndOfSupportDate'''),
    ],

    "DeviceTvmSoftwareVulnerabilities": [
        ("Devices vulnerable to a specific CVE",
         "Replace `<CVE-id>`.",
         '''DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId =~ "<CVE-id>"
| project DeviceName, OSPlatform, SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate'''),

        ("Critical CVEs unpatched",
         "Severity-driven priority list.",
         '''DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where VulnerabilitySeverityLevel == "Critical"
| summarize DeviceCount = dcount(DeviceName) by CveId, SoftwareName
| order by DeviceCount desc'''),
    ],

    "DeviceTvmSoftwareVulnerabilitiesKB": [
        ("Critical CVEs published in the last 30 days",
         "Patch-priority feed.",
         '''DeviceTvmSoftwareVulnerabilitiesKB
| where PublishedDate > ago(30d)
| where VulnerabilitySeverityLevel == "Critical"
| project CveId, CvssScore, IsExploitAvailable, PublishedDate
| order by PublishedDate desc'''),

        ("CVEs with public exploit + active in env",
         "Join KB with per-device coverage.",
         '''let KnownExploited = DeviceTvmSoftwareVulnerabilitiesKB
    | where IsExploitAvailable == true
    | project CveId;
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in (KnownExploited)
| summarize DeviceCount = dcount(DeviceName), AffectedSoftware = make_set(SoftwareName)
            by CveId, VulnerabilitySeverityLevel
| order by DeviceCount desc'''),
    ],
}


# =============================================================================
# Sentinel — per-table query bundles
# =============================================================================
# Sentinel uses TimeGenerated, not Timestamp. Schema differs from Defender.
# These follow the same BluRaven house style as the Defender ones.

SENTINEL_QUERIES: dict[str, list[tuple[str, str, str]]] = {

    "SigninLogs": [
        ("Failed sign-ins for a user",
         "Replace `<user@domain>`. Useful for triaging an account-takeover ticket.",
         '''SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ "<user@domain>"
| where ResultType != 0
| project TimeGenerated, IPAddress, AppDisplayName, ResultType,
          ResultDescription, RiskLevelDuringSignIn,
          ConditionalAccessStatus, ClientAppUsed
| order by TimeGenerated desc'''),

        ("Impossible travel — same user, two countries within 60 minutes",
         "Successful sign-ins from geographically impossible locations — pivot for compromised credentials.",
         '''let WindowMinutes = 60;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| where isnotempty(Country)
| project TimeGenerated, UserPrincipalName, Country, IPAddress, AppDisplayName
| order by UserPrincipalName asc, TimeGenerated asc
| extend Prev = prev(Country),
         PrevTime = prev(TimeGenerated),
         PrevAcct = prev(UserPrincipalName)
| where UserPrincipalName == PrevAcct
   and Country != Prev
   and datetime_diff('minute', TimeGenerated, PrevTime) <= WindowMinutes
| project UserPrincipalName, From = Prev, FromTime = PrevTime,
          To = Country, ToTime = TimeGenerated,
          MinutesDelta = datetime_diff('minute', TimeGenerated, PrevTime),
          IPAddress, AppDisplayName
| order by ToTime desc'''),

        ("Legacy authentication still in use",
         "`Other clients` = POP/IMAP/SMTP basic-auth. Should be zero in modern tenants.",
         '''SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed == "Other clients"
| where ResultType == 0
| summarize Sessions = count() by UserPrincipalName, IPAddress, AppDisplayName
| order by Sessions desc'''),

        ("Risky sign-ins (Identity Protection)",
         "Medium / high risk surfaced by AAD risk scoring.",
         '''SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("medium","high")
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          RiskLevelDuringSignIn, RiskState, RiskEventTypes_V2
| order by TimeGenerated desc'''),

        ("Conditional-Access blocked sign-ins",
         "CA Failures — useful for spotting attacker workflows that hit your gates.",
         '''SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus == "Failure"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          ResultDescription, ConditionalAccessPolicies
| order by TimeGenerated desc'''),

        ("MFA challenge failures (push-bombing detector)",
         "Repeated MFA challenges to the same user from the same source.",
         '''SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 50158        // MFA Challenge required / failed
| summarize Attempts = count(), FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where Attempts > 3
| order by Attempts desc'''),

        ("First sign-in to a new SaaS app",
         "App with zero history that suddenly gets a successful sign-in — illicit-consent risk.",
         '''SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where AppDisplayName !in~ ("Microsoft Authenticator","Office 365","Microsoft Office",
                              "Microsoft Teams","Microsoft Edge","Outlook")
| summarize FirstSeen = min(TimeGenerated), Users = dcount(UserPrincipalName),
            UserList = make_set(UserPrincipalName, 20)
            by AppDisplayName, AppId
| where FirstSeen > ago(2h)
| order by FirstSeen desc'''),

        ("Sign-ins from anonymous proxy IPs",
         "Tor / VPN / abuse-listed sources.",
         '''SigninLogs
| where TimeGenerated > ago(7d)
| where RiskEventTypes_V2 has_any ("anonymizedIPAddress","tor")
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          ResultType, RiskLevelDuringSignIn
| order by TimeGenerated desc'''),
    ],

    "SecurityEvent": [
        ("Failed interactive logons (4625)",
         "Brute-force / credential-spray triage. Excludes machine-accounts and service logons.",
         '''SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where Account !endswith "$"
| where LogonType in (2, 10)        // Interactive, RemoteInteractive
| summarize Failures = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            Targets = dcount(Computer)
            by Account, IpAddress, FailureReason
| where Failures > 5
| order by Failures desc'''),

        ("New process creation (4688)",
         "Requires Audit Process Creation policy + 'Include command line in process creation events'.",
         '''SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where Account !endswith "$"
| project TimeGenerated, Computer, Account,
          NewProcessName, CommandLine, ParentProcessName,
          TokenElevationType
| order by TimeGenerated desc'''),

        ("Office app spawning a script host (4688)",
         "Word/Excel/Outlook spawning powershell/cmd/wscript — macro-payload signature.",
         '''SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where Account !endswith "$"
| where ParentProcessName endswith "\\winword.exe"
   or ParentProcessName endswith "\\excel.exe"
   or ParentProcessName endswith "\\powerpnt.exe"
   or ParentProcessName endswith "\\outlook.exe"
| where NewProcessName endswith "\\powershell.exe"
   or NewProcessName endswith "\\cmd.exe"
   or NewProcessName endswith "\\wscript.exe"
   or NewProcessName endswith "\\cscript.exe"
   or NewProcessName endswith "\\mshta.exe"
| project TimeGenerated, Computer, Account,
          ParentProcessName, NewProcessName, CommandLine'''),

        ("PowerShell with -EncodedCommand (decode inline)",
         "Decodes the base64 payload right in the result — same as the Defender pattern.",
         '''SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where Account !endswith "$"
| where NewProcessName endswith "\\powershell.exe" or NewProcessName endswith "\\pwsh.exe"
| where CommandLine has_any ("-EncodedCommand","-enc ","-EC ")
| extend B64 = extract(@"(?i)(?:-(?:e(?:nc(?:odedcommand)?)?))\\s+([A-Za-z0-9+/=]{20,})", 1, CommandLine)
| extend Decoded = base64_decode_tostring(B64)
| project TimeGenerated, Computer, Account, CommandLine, B64, Decoded
| order by TimeGenerated desc'''),

        ("RDP from public IP (4624 LogonType 10)",
         "Successful RemoteInteractive from a public source — high-priority review.",
         '''SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where LogonType == 10            // RemoteInteractive (RDP)
| where ipv4_is_private(IpAddress) == false
| where Account !endswith "$"
| project TimeGenerated, Computer, Account, IpAddress, WorkstationName,
          AuthenticationPackageName
| order by TimeGenerated desc'''),

        ("Service installation (4697)",
         "Direct service-install signal — pair with image path under user-writable dir for persistence.",
         '''SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4697
| where SubjectUserName !endswith "$"
| project TimeGenerated, Computer, SubjectUserName, ServiceName,
          ServiceFileName, ServiceType, ServiceStartType, ServiceAccount
| order by TimeGenerated desc'''),

        ("LSASS object access (4663)",
         "Anything reading LSASS memory that isn't a Microsoft signed component is suspect.",
         '''SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4663
| where ObjectName endswith "\\lsass.exe"
| where Account !endswith "$"
| project TimeGenerated, Computer, Account, ObjectName, ProcessName,
          AccessMask, AccessReason'''),

        ("Account created (4720)",
         "New local user account.",
         '''SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4720
| project TimeGenerated, Computer, SubjectUserName, TargetUserName,
          TargetDomainName'''),

        ("After-hours interactive logon",
         "Tune the hour bounds for your business. Default: 21:00–06:00 local.",
         '''SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where LogonType == 2           // Interactive
| where Account !endswith "$"
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour >= 21 or Hour < 6
| project TimeGenerated, Hour, Computer, Account, IpAddress
| order by TimeGenerated desc'''),
    ],

    "AuditLogs": [
        ("Privileged-role membership changes",
         "Adds to Global Admin / Privileged Role Admin / App Admin.",
         '''AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Add member to role"
| extend RoleName = tostring(parse_json(tostring(TargetResources))[0].displayName),
         Member = tostring(parse_json(tostring(TargetResources))[1].displayName),
         Initiator = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where RoleName has_any ("Global Administrator","Privileged Role Administrator",
                           "Application Administrator","User Access Administrator",
                           "Cloud Application Administrator")
| project TimeGenerated, Initiator, Member, RoleName, Result'''),

        ("New OAuth app consent grants",
         "User consenting to a third-party app — illicit-consent attack precursor.",
         '''AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Consent to application"
| where Result =~ "success"
| extend AppName = tostring(parse_json(tostring(TargetResources))[0].displayName),
         User = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| project TimeGenerated, OperationName, User, AppName, Result, AdditionalDetails
| order by TimeGenerated desc'''),

        ("Password resets (forced or self-service)",
         "Common pre-impersonation step.",
         '''AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in~ ("Reset password (by admin)","Reset user password",
                            "Self-service password reset")
| extend Initiator = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName),
         Target = tostring(parse_json(tostring(TargetResources))[0].userPrincipalName)
| project TimeGenerated, OperationName, Initiator, Target, Result'''),

        ("New service principal / application created",
         "Pivot for OAuth-app-based persistence.",
         '''AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in~ ("Add service principal","Add application")
| extend AppName = tostring(parse_json(tostring(TargetResources))[0].displayName),
         User = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| project TimeGenerated, OperationName, User, AppName, Result'''),
    ],

    "OfficeActivity": [
        ("New mailbox inbox rules",
         "BEC artefact — attacker forwards / hides inbound mail.",
         '''OfficeActivity
| where TimeGenerated > ago(7d)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule","Set-InboxRule")
| where ResultStatus == "Succeeded"
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
| order by TimeGenerated desc'''),

        ("Mass file download from SharePoint / OneDrive",
         "Exfil via file-share. Tune the > 100 threshold to estate baseline.",
         '''OfficeActivity
| where TimeGenerated > ago(7d)
| where OfficeWorkload in ("SharePoint","OneDrive")
| where Operation =~ "FileDownloaded"
| summarize Files = dcount(SourceFileName), Sites = make_set(Site_Url, 10)
            by UserId, bin(TimeGenerated, 5m)
| where Files > 100
| order by Files desc'''),

        ("External-domain user accessing internal SharePoint",
         "External-collab risk.",
         '''OfficeActivity
| where TimeGenerated > ago(7d)
| where OfficeWorkload == "SharePoint"
| where Operation in~ ("FileAccessed","FileDownloaded","ListItemViewed")
| where UserId !endswith "@yourdomain.com"
| project TimeGenerated, UserId, Operation, Site_Url, SourceFileName, ClientIP'''),

        ("Teams external-tenant chat",
         "Tenant-boundary-crossing chats — potential vishing setup.",
         '''OfficeActivity
| where TimeGenerated > ago(7d)
| where OfficeWorkload == "MicrosoftTeams"
| where Operation in~ ("MessageSent","ChatCreated","TeamsImpersonationDetected")
| project TimeGenerated, UserId, Operation, Subject, Recipients,
          ClientIP, UserAgent
| order by TimeGenerated desc'''),
    ],

    "AzureActivity": [
        ("Role-assignment writes outside known IT",
         "RBAC changes are crown-jewel events.",
         '''AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue =~ "Microsoft.Authorization/roleAssignments/write"
| where ActivityStatusValue == "Succeeded"
| project TimeGenerated, Caller, CallerIpAddress, ResourceId,
          OperationNameValue, Properties'''),

        ("Key Vault secret reads",
         "Frequent reads from a single caller can indicate credential-harvesting.",
         '''AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue =~ "Microsoft.KeyVault/vaults/secrets/read"
| where ActivityStatusValue == "Succeeded"
| summarize Reads = count(), Vaults = dcount(ResourceId),
            Secrets = dcount(tostring(parse_json(tostring(Properties)).resource))
            by Caller, CallerIpAddress
| order by Reads desc'''),

        ("Storage account public-access changes",
         "Storage-container public-blob exposure.",
         '''AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "Microsoft.Storage/storageAccounts"
| where OperationNameValue has "write"
| project TimeGenerated, Caller, CallerIpAddress, ResourceId,
          OperationNameValue, ActivityStatusValue, Properties
| order by TimeGenerated desc'''),
    ],

    "Syslog": [
        ("Failed sudo attempts",
         "Linux brute-force / privilege-test signal.",
         '''Syslog
| where TimeGenerated > ago(24h)
| where Facility =~ "authpriv"
| where SyslogMessage has "sudo:" and SyslogMessage has "FAILED"
| project TimeGenerated, Computer, HostIP, SyslogMessage
| order by TimeGenerated desc'''),

        ("SSH key-based logon",
         "Tracks publickey auth — useful for pivoting on lateral movement.",
         '''Syslog
| where TimeGenerated > ago(7d)
| where ProcessName =~ "sshd"
| where SyslogMessage has "Accepted publickey"
| extend SrcIp = extract(@"from\\s+(\\S+)", 1, SyslogMessage),
         User  = extract(@"for\\s+(\\S+)\\s+from", 1, SyslogMessage)
| project TimeGenerated, Computer, User, SrcIp, SyslogMessage'''),

        ("Audit-policy / sudoers modifications",
         "Tampering with audit infrastructure.",
         '''Syslog
| where TimeGenerated > ago(7d)
| where Facility =~ "authpriv" or Facility =~ "auth"
| where SyslogMessage has_any ("/etc/sudoers","/etc/audit","auditctl",
                                "auditd","sudoers.d")
| project TimeGenerated, Computer, ProcessName, SyslogMessage'''),
    ],

    "DnsEvents": [
        ("Queries to suspect TLDs",
         "Onion / russian / tonkin TLDs.",
         '''DnsEvents
| where TimeGenerated > ago(7d)
| where Name endswith ".onion" or Name endswith ".duckdns.org"
| project TimeGenerated, Computer, ClientIP, Name, QueryTypeName, ResultCodeName'''),

        ("DNS-tunnel candidate (TXT-heavy)",
         "Frequent TXT lookups from one source — DNS-tunneling exfil.",
         '''DnsEvents
| where TimeGenerated > ago(24h)
| where QueryTypeName == "TXT"
| summarize Queries = count(), DistinctNames = dcount(Name)
            by ClientIP, bin(TimeGenerated, 5m)
| where Queries > 200
| order by Queries desc'''),
    ],

    "CommonSecurityLog": [
        ("Firewall denies from public sources",
         "Vendor-agnostic FW deny digest. Pin DeviceVendor + DeviceProduct first.",
         '''CommonSecurityLog
| where TimeGenerated > ago(24h)
| where Activity has "deny" or DeviceAction has "deny"
| where ipv4_is_private(SourceIP) == false
| summarize Hits = count() by DeviceVendor, DeviceProduct,
            SourceIP, DestinationIP, DestinationPort, DeviceAction
| order by Hits desc'''),

        ("Web-proxy threat-categorised hits",
         "Vendor-specific category mapping — adjust to your tenant's connector.",
         '''CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor =~ "Zscaler"
| where DeviceCustomString1 has_any ("malware","phishing","botnet","spyware")
| project TimeGenerated, SourceIP, SourceUserName,
          DestinationHostName, RequestURL, DeviceCustomString1'''),

        ("File hash matches (NGFW IPS / Sandbox)",
         "Replace `<bad-hash>`.",
         '''CommonSecurityLog
| where TimeGenerated > ago(7d)
| where FileHash =~ "<bad-hash>"
| project TimeGenerated, DeviceVendor, DeviceProduct, FileName, FileHash,
          SourceIP, DestinationIP, RequestURL, Message'''),
    ],

    "ThreatIntelligenceIndicator": [
        ("Active TI feed sweep against network logs",
         "Pulls all active TI indicators and sweeps against CommonSecurityLog destinations.",
         '''let Active = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true and ExpirationDateTime > now()
    | summarize arg_max(TimeGenerated, *) by IndicatorId
    | where isnotempty(NetworkIP);
CommonSecurityLog
| where TimeGenerated > ago(7d)
| join kind=inner (Active | project NetworkIP, ThreatType, ConfidenceScore)
    on $left.DestinationIP == $right.NetworkIP
| project TimeGenerated, SourceIP, SourceUserName, DestinationIP,
          ThreatType, ConfidenceScore, Activity'''),

        ("File-hash IOC sweep",
         "TI indicator hashes vs. SecurityEvent / ImFileEvent file telemetry.",
         '''let BadHashes = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where isnotempty(FileHashValue)
    | distinct FileHashValue;
ImFileEvent
| where TimeGenerated > ago(7d)
| where TargetFileSHA256 in (BadHashes) or TargetFileSHA1 in (BadHashes)
   or TargetFileMD5 in (BadHashes)
| project TimeGenerated, DvcHostname, ActorUsername, TargetFileName,
          TargetFilePath, TargetFileSHA256'''),
    ],

    "SecurityAlert": [
        ("High-severity alerts from MDE / Defender for Identity",
         "Severity-scoped triage feed.",
         '''SecurityAlert
| where TimeGenerated > ago(24h)
| where AlertSeverity in ("High","Medium")
| where ProviderName has_any ("MDATP","AAD Identity Protection","Azure Sentinel",
                                "MicrosoftDefenderForCloud","ASC")
| project TimeGenerated, AlertName, AlertSeverity, ProviderName,
          CompromisedEntity, Description'''),

        ("Per-host incident summary",
         "Group alerts by impacted host for triage.",
         '''SecurityAlert
| where TimeGenerated > ago(7d)
| extend Hosts = parse_json(Entities)
| mv-expand Hosts
| where tostring(Hosts.Type) == "host"
| extend Host = tostring(Hosts.HostName)
| summarize Alerts = count(), Names = make_set(AlertName, 5),
            FirstSeen = min(TimeGenerated)
            by Host, AlertSeverity
| order by Alerts desc'''),
    ],

    "ImProcessCreate": [
        ("Cross-vendor process create — Office spawning script host",
         "Same shape as the SecurityEvent 4688 query but vendor-agnostic via ASIM.",
         '''ImProcessCreate
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where ParentProcessName in~ ("winword.exe","excel.exe","powerpnt.exe",
                                 "outlook.exe","onenote.exe")
| where TargetProcessName in~ ("powershell.exe","pwsh.exe","cmd.exe",
                                 "wscript.exe","cscript.exe","mshta.exe")
| project TimeGenerated, DvcHostname, ActorUsername,
          ParentProcessName, TargetProcessName, TargetProcessCommandLine
| order by TimeGenerated desc'''),

        ("LOLBin executions (cross-vendor)",
         "Living-off-the-land binaries normalised across MDE / Sysmon / AuditD / etc.",
         '''ImProcessCreate
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where TargetProcessName in~ ("certutil.exe","bitsadmin.exe","mshta.exe",
                                 "regsvr32.exe","rundll32.exe","wmic.exe",
                                 "msbuild.exe","installutil.exe","cmstp.exe")
| project TimeGenerated, DvcHostname, ActorUsername,
          TargetProcessName, TargetProcessCommandLine, ParentProcessName'''),

        ("PowerShell with suspicious flags",
         "Hidden window, no-profile, bypass — common evasion combos.",
         '''ImProcessCreate
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where TargetProcessName in~ ("powershell.exe","pwsh.exe")
| where TargetProcessCommandLine matches regex @"(?i)-w(in)?(dow)?style?\\s+h(idden)?|-nop(rofile)?|-ep\\s+bypass|frombase64string|invoke-expression|iex\\s*\\(|net\\.webclient"
| project TimeGenerated, DvcHostname, ActorUsername,
          TargetProcessCommandLine, ParentProcessName'''),

        ("Files run from temp / AppData",
         "User-mode malware staging area.",
         '''ImProcessCreate
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where TargetProcessName has_any (@"\\AppData\\Local\\Temp\\",
                                     @"\\AppData\\Roaming\\",
                                     @"\\Windows\\Temp\\",
                                     @"\\Users\\Public\\")
| project TimeGenerated, DvcHostname, ActorUsername,
          TargetProcessName, TargetProcessCommandLine, SHA256'''),

        ("Hash IOC sweep (cross-vendor)",
         "Replace the dynamic list with article-specific hashes.",
         '''let BadHashes = dynamic(["<sha256-1>","<sha256-2>"]);
ImProcessCreate
| where TimeGenerated > ago(7d)
| where SHA256 in~ (BadHashes) or MD5 in~ (BadHashes) or SHA1 in~ (BadHashes)
| project TimeGenerated, DvcHostname, ActorUsername,
          TargetProcessName, TargetProcessCommandLine, SHA256'''),
    ],

    "ImNetworkSession": [
        ("Egress to public IP",
         "Internet-bound network sessions only.",
         '''ImNetworkSession
| where TimeGenerated > ago(24h)
| where DvcAction != "Block"
| where ipv4_is_private(DstIpAddr) == false
| project TimeGenerated, DvcHostname, SrcIpAddr, DstIpAddr,
          DstPortNumber, NetworkProtocol, NetworkBytes
| order by TimeGenerated desc'''),

        ("Beaconing detector",
         "Sustained periodic outbound to one destination — C2 signature.",
         '''ImNetworkSession
| where TimeGenerated > ago(2h)
| where ipv4_is_private(DstIpAddr) == false
| summarize ConnCount = count(),
            DistinctMinutes = dcount(bin(TimeGenerated, 1m))
            by DvcHostname, DstIpAddr, DstPortNumber
| where ConnCount > 50 and DistinctMinutes > 30
| order by ConnCount desc'''),

        ("Connections to a domain pattern",
         "Use Url field for HTTP-aware connectors. Replace `<pattern>`.",
         '''ImNetworkSession
| where TimeGenerated > ago(7d)
| where Url has "<pattern>"
| project TimeGenerated, DvcHostname, SrcIpAddr, Url,
          DstIpAddr, DstPortNumber, NetworkProtocol'''),
    ],

    "ImAuthentication": [
        ("Cross-vendor authentication failures",
         "Aggregates failed auth across cloud + on-prem connectors.",
         '''ImAuthentication
| where TimeGenerated > ago(24h)
| where EventResult == "Failure"
| where TargetUsername !endswith "$"
| summarize Failures = count(), FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by TargetUsername, SrcIpAddr, EventVendor
| where Failures > 5
| order by Failures desc'''),

        ("Anomalous logon protocol",
         "NTLM where Kerberos is expected — pivot signal.",
         '''ImAuthentication
| where TimeGenerated > ago(7d)
| where EventResult == "Success"
| where LogonProtocol =~ "NTLM"
| where TargetUsername !endswith "$"
| project TimeGenerated, DvcHostname, TargetUsername, SrcIpAddr,
          LogonProtocol, LogonMethod, EventVendor
| order by TimeGenerated desc'''),
    ],

    "ImFileEvent": [
        ("File creates in suspect paths",
         "User-mode malware staging.",
         '''ImFileEvent
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where EventType == "FileCreated"
| where TargetFilePath has_any (@"\\AppData\\Local\\Temp\\",
                                  @"\\AppData\\Roaming\\",
                                  @"\\Windows\\Temp\\")
| where TargetFileName endswith ".exe" or TargetFileName endswith ".dll"
   or TargetFileName endswith ".ps1"
| project TimeGenerated, DvcHostname, ActorUsername, TargetFilePath,
          TargetFileName, TargetFileSHA256'''),

        ("Cross-vendor mass file rename (ransomware)",
         "Threshold-based encryption signal across MDE / Sysmon / AuditD.",
         '''ImFileEvent
| where TimeGenerated > ago(1d)
| where ActorUsername !endswith "$"
| where EventType in ("FileRenamed","FileModified")
| summarize files = dcount(TargetFileName)
            by DvcHostname, ActorUsername, ActingProcessName, bin(TimeGenerated, 1m)
| where files > 200
| order by files desc'''),
    ],

    "ImDnsActivity": [
        ("Cross-vendor DNS queries to suspect TLDs",
         "Normalised across Win DNS, Sysmon EID 22, Linux dnsmasq.",
         '''ImDnsActivity
| where TimeGenerated > ago(7d)
| where DnsQuery endswith ".onion"
   or DnsQuery endswith ".ru"
   or DnsQuery endswith ".su"
| project TimeGenerated, DvcHostname, SrcIpAddr, DnsQuery,
          DnsQueryTypeName, DnsResponseCodeName'''),

        ("DNS-tunnel signature (TXT-heavy)",
         "TXT-query volume per source.",
         '''ImDnsActivity
| where TimeGenerated > ago(24h)
| where DnsQueryTypeName == "TXT"
| summarize Queries = count(), DistinctNames = dcount(DnsQuery)
            by SrcIpAddr, bin(TimeGenerated, 5m)
| where Queries > 200
| order by Queries desc'''),
    ],

    "ImRegistryEvent": [
        ("Run / RunOnce changes",
         "Persistence-key writes — cross-vendor normalisation.",
         '''ImRegistryEvent
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where RegistryKey has_any (@"\\Run", @"\\RunOnce")
| where ActingProcessName !in~ ("msiexec.exe","explorer.exe")
| project TimeGenerated, DvcHostname, ActorUsername,
          RegistryKey, RegistryValue, RegistryValueData, ActingProcessName'''),

        ("IFEO debugger hijack",
         "Image File Execution Options debugger override — classic evasion.",
         '''ImRegistryEvent
| where TimeGenerated > ago(7d)
| where ActorUsername !endswith "$"
| where RegistryKey has @"\\Image File Execution Options\\"
| where RegistryValue =~ "Debugger"
| project TimeGenerated, DvcHostname, RegistryKey, RegistryValueData,
          ActingProcessName'''),
    ],
}


# =============================================================================
# Splunk SPL — curated queries per CIM datamodel.
#
# SPLUNK_DATAMODELS is the "schema" we render in the schema-collapse under
# each datamodel header. SPLUNK_QUERIES is the analyst-shift query set —
# triage starts, pivots by host/user/IP, common slices. House style:
#   • tstats over CIM datamodels for fast queries when CIM acceleration
#     is enabled (use the `summariesonly` macro)
#   • drop_dm_object_name(<DM>) to flatten object-prefixed fields
#   • Times in -24h@h / now style
#   • <placeholder> fields the analyst replaces during a shift
# =============================================================================

SPLUNK_DATAMODELS: dict[str, list[str]] = {
    "Endpoint.Processes": [
        "_time", "host", "dest", "user", "process_name", "process_path",
        "process", "process_id", "process_guid", "process_hash",
        "parent_process_name", "parent_process_path", "parent_process",
        "parent_process_id", "parent_process_guid", "process_integrity_level",
        "action", "vendor_product", "user_id", "session_id",
    ],
    "Endpoint.Filesystem": [
        "_time", "host", "dest", "user", "file_name", "file_path",
        "file_hash", "file_size", "file_create_time", "file_modify_time",
        "action", "process_name", "process_path", "process_id",
        "vendor_product",
    ],
    "Endpoint.Registry": [
        "_time", "host", "dest", "user", "registry_path",
        "registry_key_name", "registry_value_name", "registry_value_data",
        "registry_value_type", "action", "process_name", "process_id",
        "vendor_product",
    ],
    "Network_Traffic.All_Traffic": [
        "_time", "src", "dest", "src_ip", "dest_ip", "src_port", "dest_port",
        "transport", "protocol", "action", "bytes", "bytes_in", "bytes_out",
        "packets", "duration", "user", "process", "rule",
        "vendor_product", "src_category", "dest_category",
    ],
    "Authentication.Authentication": [
        "_time", "src", "dest", "user", "src_user", "src_user_id",
        "user_id", "action", "app", "authentication_method",
        "authentication_service", "duration", "session_id",
        "signature", "signature_id", "reason", "vendor_product",
    ],
    "Web.Web": [
        "_time", "src", "dest", "user", "url", "url_domain", "url_length",
        "uri_path", "uri_query", "http_method", "http_user_agent",
        "http_content_type", "http_referrer", "status", "response_time",
        "bytes", "bytes_in", "bytes_out", "category",
    ],
    "Network_Resolution.DNS": [
        "_time", "src", "dest", "src_ip", "dest_ip", "query", "query_type",
        "answer", "reply_code", "reply_code_id", "transport",
        "duration", "vendor_product",
    ],
    "Email.All_Email": [
        "_time", "src_user", "recipient", "subject", "message_id",
        "internal_message_id", "message_size", "delay", "filename",
        "file_hash", "url", "src", "src_ip", "vendor_product", "action",
    ],
}


SPLUNK_QUERIES: dict[str, list[tuple[str, str, str]]] = {
    "Endpoint.Processes": [
        ("All processes for a user",
         "User triage — every process exec tied to one identity in the last 24h. Replace `<UserName>`.",
         '''| tstats `summariesonly` count, values(Processes.process) AS process, values(Processes.parent_process_name) AS parent
    from datamodel=Endpoint.Processes
    where Processes.user=<UserName> earliest=-24h@h
    by Processes.dest, Processes.process_name, _time span=10m
| `drop_dm_object_name(Processes)`
| sort -_time'''),

        ("All processes on a host",
         "Host triage — every process exec on one device. Replace `<DeviceName>`.",
         '''| tstats `summariesonly` count, values(Processes.process) AS process, values(Processes.parent_process_name) AS parent
    from datamodel=Endpoint.Processes
    where Processes.dest=<DeviceName> earliest=-24h@h
    by Processes.user, Processes.process_name, _time span=1m
| `drop_dm_object_name(Processes)`
| sort -_time'''),

        ("Children of a specific process",
         "What did `<parent.exe>` spawn? Replace the parent process name.",
         '''| tstats `summariesonly` count, values(Processes.process) AS cmdline
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name=<parent.exe> earliest=-24h@h
    by Processes.dest, Processes.user, Processes.process_name'''),

        ("Find every host that ran a binary",
         "Binary-name pivot. Replace `<binary.exe>`.",
         '''| tstats `summariesonly` count, min(_time) AS first_seen, max(_time) AS last_seen
    from datamodel=Endpoint.Processes
    where Processes.process_name=<binary.exe> earliest=-7d@d
    by Processes.dest, Processes.user, Processes.process'''),

        ("Find every host that ran a hash",
         "IOC pivot — every host that ran a binary with this SHA256. Replace `<sha256>`.",
         '''| tstats `summariesonly` count, min(_time) AS first_seen, max(_time) AS last_seen
    from datamodel=Endpoint.Processes
    where Processes.process_hash=<sha256> earliest=-30d@d
    by Processes.dest, Processes.user, Processes.process_name, Processes.process'''),

        ("Process tree for a user during a time window",
         "Reconstruct what a user was doing between `<start>` and `<end>` (use `-2h@h`, `-30m@m`, etc).",
         '''| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.user=<UserName> earliest=<start> latest=<end>
    by _time, Processes.dest, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| sort _time'''),
    ],

    "Endpoint.Filesystem": [
        ("All file activity on a host",
         "Host triage — every create / modify / delete on one device. Replace `<DeviceName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.dest=<DeviceName> earliest=-24h@h
    by Filesystem.user, Filesystem.action, Filesystem.process_name, Filesystem.file_path, Filesystem.file_name, _time span=10m
| sort -_time'''),

        ("All file activity for a user",
         "User triage. Replace `<UserName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.user=<UserName> earliest=-24h@h
    by Filesystem.dest, Filesystem.action, Filesystem.process_name, Filesystem.file_path, Filesystem.file_name'''),

        ("Files written by a process",
         "What did `<binary.exe>` create? Replace the process name.",
         '''| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created" Filesystem.process_name=<binary.exe> earliest=-24h@h
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name'''),

        ("Files written under a directory path",
         "Directory pivot. Replace `<path-fragment>` (e.g. `\\\\AppData\\\\Local\\\\Temp\\\\`).",
         '''| tstats `summariesonly` count, values(Filesystem.process_name) AS writers
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created" Filesystem.file_path="*<path-fragment>*" earliest=-24h@h
    by Filesystem.dest, Filesystem.user, Filesystem.file_name'''),

        ("Hash-IOC sweep across the fleet",
         "Was this hash ever written? Replace `<sha256>`.",
         '''| tstats `summariesonly` count, values(Filesystem.dest) AS hosts
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash=<sha256> earliest=-30d@d
    by Filesystem.file_name'''),
    ],

    "Endpoint.Registry": [
        ("All registry activity on a host",
         "Host triage — every registry write / modify / delete on one device. Replace `<DeviceName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Endpoint.Registry
    where Registry.dest=<DeviceName> earliest=-24h@h
    by Registry.user, Registry.action, Registry.process_name, Registry.registry_path, Registry.registry_value_name'''),

        ("Registry activity for a user",
         "User triage. Replace `<UserName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Endpoint.Registry
    where Registry.user=<UserName> earliest=-24h@h
    by Registry.dest, Registry.action, Registry.process_name, Registry.registry_path'''),

        ("Registry writes under a key path",
         "Key-path pivot. Replace `<path-fragment>` (e.g. `\\\\Run\\\\` or `\\\\Services\\\\`).",
         '''| tstats `summariesonly` count
    from datamodel=Endpoint.Registry
    where Registry.action in ("created","modified")
        and Registry.registry_path="*<path-fragment>*" earliest=-24h@h
    by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_data'''),

        ("Find which process wrote a registry value",
         "Pivot for an interesting key — who set it? Replace `<value-name>`.",
         '''| tstats `summariesonly` count, values(Registry.registry_value_data) AS data
    from datamodel=Endpoint.Registry
    where Registry.registry_value_name=<value-name> Registry.action in ("created","modified")
        earliest=-7d@d
    by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path'''),
    ],

    "Network_Traffic.All_Traffic": [
        ("All outbound from a host",
         "Host triage — every allowed outbound connection. Replace `<DeviceName>`.",
         '''| tstats `summariesonly` count, sum(All_Traffic.bytes_out) AS bytes_out
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src=<DeviceName>
        and All_Traffic.action="allowed"
        earliest=-24h@h
    by All_Traffic.dest, All_Traffic.dest_port, _time span=10m
| `drop_dm_object_name(All_Traffic)`
| sort -_time'''),

        ("All connections to an IP",
         "IP IOC pivot — every host that talked to it. Replace `<IP>`.",
         '''| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports, sum(All_Traffic.bytes_out) AS bytes_out
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest_ip=<IP> earliest=-7d@d
    by All_Traffic.src, All_Traffic.user'''),

        ("All connections on a port from a host",
         "Port-specific triage. Replace `<DeviceName>` and `<port>` (e.g. 3389, 22, 445).",
         '''| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src=<DeviceName>
        and All_Traffic.dest_port=<port> earliest=-24h@h
    by All_Traffic.dest, All_Traffic.action, _time span=5m'''),

        ("Top destinations for a host",
         "What's a host been talking to most? Useful for first-look beaconing review.",
         '''| tstats `summariesonly` count, sum(All_Traffic.bytes_out) AS bytes_out
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src=<DeviceName>
        and All_Traffic.action="allowed" earliest=-24h@h
    by All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| sort - count'''),

        ("Failed / denied connections from a host",
         "What's the firewall blocking from this host? Replace `<DeviceName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src=<DeviceName>
        and All_Traffic.action!="allowed" earliest=-24h@h
    by All_Traffic.dest, All_Traffic.dest_port, All_Traffic.action'''),
    ],

    "Authentication.Authentication": [
        ("All authentication events for a user",
         "User triage — every login (success + fail) for one identity. Replace `<UserName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.user=<UserName> earliest=-24h@h
    by Authentication.action, Authentication.src, Authentication.dest, _time span=10m
| `drop_dm_object_name(Authentication)`
| sort -_time'''),

        ("All logins from an IP",
         "IP pivot — every account this address has authenticated against. Replace `<IP>`.",
         '''| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.src=<IP> earliest=-7d@d
    by Authentication.user, Authentication.action, Authentication.dest'''),

        ("Logins to a specific host",
         "Host pivot — who's logged on (and tried to log on) here? Replace `<DeviceName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.dest=<DeviceName> earliest=-24h@h
    by Authentication.user, Authentication.src, Authentication.action'''),

        ("Failed authentications for a user",
         "Fast triage on a user's failures. Replace `<UserName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.action="failure" Authentication.user=<UserName> earliest=-24h@h
    by Authentication.src, Authentication.dest, Authentication.reason, _time span=10m'''),

        ("All source IPs a user has used",
         "Find the geographic / network footprint for one identity. Replace `<UserName>`.",
         '''| tstats `summariesonly` values(Authentication.src) AS src_ips, count
    from datamodel=Authentication.Authentication
    where Authentication.action="success" Authentication.user=<UserName> earliest=-30d@d
    by Authentication.user'''),
    ],

    "Web.Web": [
        ("All HTTP traffic for a user",
         "User triage — every web request for one identity. Replace `<UserName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Web.Web
    where Web.user=<UserName> earliest=-24h@h
    by Web.url_domain, Web.http_method, Web.status, _time span=10m'''),

        ("All HTTP traffic from a source",
         "Source pivot. Replace `<src>` with hostname or IP.",
         '''| tstats `summariesonly` count, sum(Web.bytes_out) AS bytes_out
    from datamodel=Web.Web
    where Web.src=<src> earliest=-24h@h
    by Web.url_domain, Web.http_method, Web.status'''),

        ("All requests to a domain",
         "Domain pivot — every host that fetched it. Replace `<domain>`.",
         '''| tstats `summariesonly` count, values(Web.url) AS urls
    from datamodel=Web.Web
    where Web.url_domain=<domain> earliest=-7d@d
    by Web.src, Web.user, Web.http_method, Web.status'''),

        ("Requests with a User-Agent",
         "UA pivot — find every host using a specific UA. Replace `<UA-fragment>`.",
         '''| tstats `summariesonly` count
    from datamodel=Web.Web
    where Web.http_user_agent="*<UA-fragment>*" earliest=-24h@h
    by Web.src, Web.url_domain, Web.http_user_agent'''),

        ("Top domains for a user",
         "What's a user been browsing most? Replace `<UserName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Web.Web
    where Web.user=<UserName> earliest=-24h@h
    by Web.url_domain
| `drop_dm_object_name(Web)`
| sort - count'''),
    ],

    "Network_Resolution.DNS": [
        ("All DNS queries from a host",
         "Host triage — every name resolution from one device. Replace `<DeviceName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Network_Resolution.DNS
    where DNS.src=<DeviceName> earliest=-24h@h
    by DNS.query, DNS.query_type, DNS.reply_code'''),

        ("Hosts that resolved a domain",
         "Domain pivot — every device that asked for it. Replace `<domain>`.",
         '''| tstats `summariesonly` count, min(_time) AS first_seen, max(_time) AS last_seen
    from datamodel=Network_Resolution.DNS
    where DNS.query=<domain> earliest=-7d@d
    by DNS.src'''),

        ("DNS queries that resolved to an IP",
         "IP-back-pivot — what names point to this address? Replace `<IP>`.",
         '''| tstats `summariesonly` count
    from datamodel=Network_Resolution.DNS
    where DNS.answer=<IP> earliest=-7d@d
    by DNS.query, DNS.src'''),

        ("Top domains for a host",
         "What's a host been resolving most? Replace `<DeviceName>`.",
         '''| tstats `summariesonly` count
    from datamodel=Network_Resolution.DNS
    where DNS.src=<DeviceName> earliest=-24h@h
    by DNS.query
| `drop_dm_object_name(DNS)`
| sort - count'''),

        ("DNS failures from a host",
         "NXDOMAIN / SERVFAIL responses — failed C2 / DGA / typo-squat indicator.",
         '''| tstats `summariesonly` count
    from datamodel=Network_Resolution.DNS
    where DNS.src=<DeviceName>
        and DNS.reply_code in ("NXDOMAIN","SERVFAIL","REFUSED") earliest=-24h@h
    by DNS.query, DNS.reply_code'''),
    ],

    "Email.All_Email": [
        ("All inbound for a recipient",
         "Recipient triage — every email this user received. Replace `<email>`.",
         '''| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where Email.recipient=<email> earliest=-7d@d
    by Email.src_user, Email.subject, Email.action, _time span=1h
| sort -_time'''),

        ("All emails from a sender",
         "Sender pivot. Replace `<email-or-domain>`.",
         '''| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where Email.src_user=<email-or-domain> earliest=-7d@d
    by Email.recipient, Email.subject, Email.action'''),

        ("Emails by subject",
         "Subject-line pivot. Replace `<subject-fragment>`.",
         '''| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where Email.subject="*<subject-fragment>*" earliest=-7d@d
    by Email.src_user, Email.recipient, Email.action, Email.filename'''),

        ("Emails with an attachment name / extension",
         "Filename pivot. Replace `<filename-or-ext>`.",
         '''| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where Email.filename="*<filename-or-ext>*" earliest=-7d@d
    by Email.recipient, Email.src_user, Email.filename, Email.subject'''),

        ("Emails with a URL",
         "URL pivot — every recipient who got a message containing this link. Replace `<url-fragment>`.",
         '''| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where Email.url="*<url-fragment>*" earliest=-7d@d
    by Email.recipient, Email.src_user, Email.subject'''),
    ],
}


# =============================================================================
# Datadog Cloud SIEM — curated queries per log source.
#
# DATADOG_SOURCES is the "schema" — each entry maps a `source:` value to the
# tagged-attribute paths analysts use most. It powers the schema-collapse
# section under each source header (same look as the KQL panes).
#
# DATADOG_QUERIES are the curated analyst-shift queries: discovery, hunting,
# investigation. Every body is verbatim Datadog Logs Explorer / Cloud SIEM
# syntax — `source:` first, `@field.path:value` filters, uppercase boolean
# operators, `CIDR(@ip, range)` for IP ranges. Time windows are configured
# at rule level in Datadog so they're absent from the query body.
# =============================================================================

DATADOG_SOURCES: dict[str, list[str]] = {
    "cloudtrail": [
        "@evt.name", "@evt.outcome", "@userIdentity.type", "@userIdentity.userName",
        "@userIdentity.arn", "@userIdentity.accountId", "@userIdentity.sessionContext.sessionIssuer.userName",
        "@requestParameters.userName", "@requestParameters.policyArn", "@requestParameters.bucketName",
        "@responseElements.user.userName", "@network.client.ip", "@aws.region", "@aws.account.id",
    ],
    "azure.activity_logs": [
        "@operationName.value", "@properties.eventName", "@properties.activityStatusValue",
        "@identity.claim.upn", "@identity.claim.appid", "@network.client.ip",
        "@properties.resource", "@resource.resourceGroup", "@resource.subscriptionId",
    ],
    "azure.activeDirectory": [
        "@evt.name", "@usr.id", "@usr.email", "@user.userPrincipalName",
        "@network.client.ip", "@network.client.geoip.country.iso_code",
        "@properties.status.errorCode", "@properties.appDisplayName",
        "@properties.riskState", "@properties.riskLevelDuringSignIn",
        "@properties.authenticationProtocol", "@properties.deviceDetail.deviceId",
    ],
    "windows.security": [
        "@EventID", "@Image", "@CommandLine", "@User", "@SubjectUserName",
        "@TargetUserName", "@LogonType", "@WorkstationName", "@IpAddress",
        "@ProcessName", "@ParentProcessName", "@AccessMask", "@PrivilegeList",
    ],
    "windows.sysmon": [
        "@EventID", "@Image", "@CommandLine", "@ParentImage", "@ParentCommandLine",
        "@Hashes", "@DestinationIp", "@DestinationPort", "@DestinationHostname",
        "@SourceIp", "@TargetFilename", "@TargetObject", "@User", "@LogonId",
    ],
    "linux.auditd": [
        "@process.name", "@process.command_line", "@process.executable.path",
        "@user.name", "@user.id", "@auditd.type", "@network.client.ip",
        "@network.destination.ip", "@host.name", "@auditd.uid", "@auditd.gid",
    ],
    "gcp.audit": [
        "@protoPayload.methodName", "@protoPayload.authenticationInfo.principalEmail",
        "@protoPayload.requestMetadata.callerIp", "@protoPayload.serviceName",
        "@protoPayload.resourceName", "@resource.labels.project_id",
        "@resource.type", "@severity",
    ],
    "kubernetes.audit": [
        "@verb", "@objectRef.resource", "@objectRef.name", "@objectRef.namespace",
        "@user.username", "@user.groups", "@sourceIPs",
        "@requestObject.spec.containers.image", "@requestObject.spec.hostPID",
        "@requestObject.spec.hostNetwork", "@responseStatus.code",
    ],
    "okta": [
        "@evt.name", "@actor.alternateId", "@actor.id", "@actor.displayName",
        "@client.ipAddress", "@client.geographicalContext.country",
        "@client.geographicalContext.city", "@outcome.result", "@outcome.reason",
        "@authenticationContext.authenticationProvider", "@target.alternateId",
    ],
    "slack": [
        "@evt.name", "@actor.user.email", "@actor.user.name",
        "@actor.user.team", "@context.ip_address", "@context.location.country",
        "@entity.channel", "@entity.file", "@entity.app",
    ],
    "microsoft.teams": [
        "@evt.name", "@user.userPrincipalName", "@user.id",
        "@network.client.ip", "@team.id", "@team.displayName",
        "@channel.id", "@channel.displayName", "@app.displayName",
    ],
    "salesforce": [
        "@evt.name", "@usr.id", "@usr.username", "@usr.email",
        "@network.client.ip", "@object.type", "@object.name",
        "@event.type", "@status",
    ],
}


DATADOG_QUERIES: dict[str, list[tuple[str, str, str]]] = {
    "cloudtrail": [
        ("All API activity for a specific user / role",
         "Triage starting point — every CloudTrail event from one identity. Replace `<userName>`.",
         '''source:cloudtrail @userIdentity.userName:<userName>'''),

        ("All API activity from a single source IP",
         "Pivot for an attacker IP found elsewhere (NIDS, WAF, CTI). Replace `<IP>`.",
         '''source:cloudtrail @network.client.ip:<IP>'''),

        ("All actions on a specific S3 bucket",
         "Investigate exfil / config-change on a named bucket. Replace `<bucketName>`.",
         '''source:cloudtrail @requestParameters.bucketName:<bucketName>'''),

        ("Failed actions only (any service)",
         "Quick triage of refused actions — credential-stuffing, perm-discovery, throttled abuse all live here.",
         '''source:cloudtrail @evt.outcome:failure'''),

        ("AssumeRole calls into one role",
         "Who has been assuming a privileged role? Replace `<roleName>`.",
         '''source:cloudtrail @evt.name:AssumeRole
@requestParameters.roleArn:*<roleName>*'''),

        ("Console-login attempts from foreign geos",
         "Console authentications from outside the expected business geographies.",
         '''source:cloudtrail @evt.name:ConsoleLogin
@network.client.geoip.country.iso_code:(CN OR RU OR IR OR KP OR BY)'''),
    ],

    "azure.activity_logs": [
        ("All resource activity in a resource group",
         "Triage scope: every operation against one RG. Replace `<resourceGroupName>`.",
         '''source:azure.activity_logs @resource.resourceGroup:<resourceGroupName>'''),

        ("All actions by a specific identity",
         "Pivot for an account under investigation. Replace `<upn-or-appId>`.",
         '''source:azure.activity_logs
(@identity.claim.upn:<upn-or-appId> OR @identity.claim.appid:<upn-or-appId>)'''),

        ("All resource deletions",
         "Wide net for destructive activity — sort by time and pivot on the principal.",
         '''source:azure.activity_logs
@operationName.value:*delete*
@properties.activityStatusValue:Succeeded'''),

        ("Storage-account key listings",
         "Storage-key reads bypass RBAC on data — strong signal of data-exfil tradecraft.",
         '''source:azure.activity_logs
@operationName.value:Microsoft.Storage/storageAccounts/listKeys/action'''),

        ("Failed Azure operations",
         "Search across denied/failed Azure operations, useful for permission-discovery hunts.",
         '''source:azure.activity_logs @properties.activityStatusValue:Failed'''),
    ],

    "azure.activeDirectory": [
        ("All sign-in activity for one user",
         "User triage — every sign-in (success + fail). Replace `<upn>`.",
         '''source:azure.activeDirectory @evt.name:"Sign-in activity"
@user.userPrincipalName:<upn>'''),

        ("All sign-ins from one IP",
         "Pivot for a suspicious source IP — see every account it touched. Replace `<IP>`.",
         '''source:azure.activeDirectory @evt.name:"Sign-in activity"
@network.client.ip:<IP>'''),

        ("Failed sign-ins by error code",
         "Filter to a specific failure mode (50126=bad password, 50053=locked, 50058=no session, 50158=external MFA fail). Replace `<errorCode>`.",
         '''source:azure.activeDirectory @evt.name:"Sign-in activity"
@properties.status.errorCode:<errorCode>'''),

        ("OAuth app consent grants",
         "Find every consent given to a third-party app — pivot via appDisplayName for the app footprint.",
         '''source:azure.activeDirectory
@evt.name:"Add app role assignment to service principal"'''),

        ("Sign-ins flagged risky by Identity Protection",
         "Identity Protection's risk-state field filtered to non-clean states.",
         '''source:azure.activeDirectory @evt.name:"Sign-in activity"
@properties.riskState:(atRisk OR confirmedCompromised)'''),

        ("Sign-ins from foreign geographies",
         "Quick hunt for geographically anomalous logins.",
         '''source:azure.activeDirectory @evt.name:"Sign-in activity"
@network.client.geoip.country.iso_code:(CN OR RU OR IR OR KP OR BY)'''),
    ],

    "windows.security": [
        ("All security events for one host",
         "Host triage — every Win Security event. Replace `<DeviceName>`.",
         '''source:windows.security @WorkstationName:<DeviceName>'''),

        ("Logons by a specific user",
         "EID 4624 (logon) for one identity. Replace `<UserName>`.",
         '''source:windows.security @EventID:4624
@TargetUserName:<UserName>
-@TargetUserName:*$'''),

        ("Failed logons (any user)",
         "EID 4625 — all logon failures. Tune by IP / WorkstationName for hunt.",
         '''source:windows.security @EventID:4625
-@TargetUserName:*$'''),

        ("Account lockouts",
         "EID 4740 — accounts that hit the lockout threshold. Pivot for credential-spray.",
         '''source:windows.security @EventID:4740'''),

        ("Process creation by event ID 4688",
         "Process-create audit log if Sysmon isn't deployed. Replace `<binary>`.",
         '''source:windows.security @EventID:4688
@ProcessName:*<binary>*'''),

        ("Privileged group changes",
         "EID 4732/4756/4728 — adds to local-/domain-/universal-admin groups.",
         '''source:windows.security @EventID:(4732 OR 4756 OR 4728)
@TargetUserName:(*Admin* OR *Domain* OR *Enterprise*)'''),
    ],

    "windows.sysmon": [
        ("All sysmon activity on a host",
         "Host triage — full process / network / file / registry activity. Replace `<DeviceName>`.",
         '''source:windows.sysmon @host:<DeviceName>'''),

        ("Process creates by image name",
         "EID 1 — every spawn of a binary. Both casings (Datadog is case-sensitive). Replace `<binary.exe>`.",
         '''source:windows.sysmon @EventID:1
@Image:(*\\\\<binary.exe> OR *\\\\<BINARY.EXE>)'''),

        ("Network connections to a destination IP",
         "EID 3 — outbound flows to a target. Replace `<IP>`.",
         '''source:windows.sysmon @EventID:3
@DestinationIp:<IP>'''),

        ("File creates by path",
         "EID 11 — file create/modify. Useful for tracking written payloads. Replace `<path-fragment>`.",
         '''source:windows.sysmon @EventID:11
@TargetFilename:*<path-fragment>*'''),

        ("Registry writes under Run / RunOnce / Services",
         "EID 13 — persistence-key writes under classic ASEP locations.",
         '''source:windows.sysmon @EventID:13
@TargetObject:(*\\\\Run\\\\* OR *\\\\RunOnce\\\\* OR *\\\\Services\\\\* OR "*Image File Execution Options*" OR *\\\\Winlogon\\\\*)'''),

        ("Image-load (DLL) by hash",
         "EID 7 — find every host that loaded a known-bad DLL. Replace `<sha256>`.",
         '''source:windows.sysmon @EventID:7
@Hashes:*SHA256=<sha256>*'''),
    ],

    "linux.auditd": [
        ("All auditd activity on a host",
         "Host triage. Replace `<host>`.",
         '''source:linux.auditd @host.name:<host>'''),

        ("Process executions by a user",
         "EXECVE filtered to one user. Replace `<userName>`.",
         '''source:linux.auditd @auditd.type:EXECVE @user.name:<userName>'''),

        ("Find a binary by name",
         "Every EXECVE of a binary across the fleet. Replace `<binary>`.",
         '''source:linux.auditd @auditd.type:EXECVE
@process.name:<binary>'''),

        ("Outbound connections to one host",
         "Network destinations from auditd's syscall logs. Replace `<IP>`.",
         '''source:linux.auditd @network.destination.ip:<IP>'''),

        ("Files written under a path",
         "PATH events filtered to a directory. Replace `<directory>`.",
         '''source:linux.auditd @auditd.type:PATH
@auditd.path:<directory>/*'''),

        ("Authentication events for a user",
         "USER_AUTH / USER_LOGIN — pam-side authentication trail. Replace `<userName>`.",
         '''source:linux.auditd @auditd.type:(USER_AUTH OR USER_LOGIN OR USER_ACCT)
@user.name:<userName>'''),
    ],

    "gcp.audit": [
        ("All audit log activity in a project",
         "Project-level scope. Replace `<project-id>`.",
         '''source:gcp.audit @resource.labels.project_id:<project-id>'''),

        ("Activity by a specific principal",
         "Every method called by one principal email. Replace `<email>`.",
         '''source:gcp.audit
@protoPayload.authenticationInfo.principalEmail:<email>'''),

        ("Activity from one source IP",
         "Caller IP pivot. Replace `<IP>`.",
         '''source:gcp.audit
@protoPayload.requestMetadata.callerIp:<IP>'''),

        ("IAM policy changes",
         "Every SetIamPolicy across the org — pair with the bindingDeltas.member field for reach.",
         '''source:gcp.audit
@protoPayload.methodName:(SetIamPolicy OR setIamPolicy)'''),

        ("Service account key creations",
         "Long-lived credential creations — pivot for token-exfil tradecraft.",
         '''source:gcp.audit
@protoPayload.methodName:google.iam.admin.v1.CreateServiceAccountKey'''),

        ("Failed / denied operations",
         "Permission-discovery activity surfaces here.",
         '''source:gcp.audit @severity:(ERROR OR WARNING)'''),
    ],

    "kubernetes.audit": [
        ("All activity in a namespace",
         "Namespace triage. Replace `<namespace>`.",
         '''source:kubernetes.audit @objectRef.namespace:<namespace>'''),

        ("Actions by a user / service account",
         "User pivot. Replace `<username>`.",
         '''source:kubernetes.audit @user.username:<username>'''),

        ("Pods created in a namespace",
         "What got deployed where, by whom. Replace `<namespace>`.",
         '''source:kubernetes.audit
@verb:create @objectRef.resource:pods
@objectRef.namespace:<namespace>'''),

        ("Privileged / hostPID / hostNetwork pod specs",
         "Container break-out primitives.",
         '''source:kubernetes.audit @verb:create @objectRef.resource:pods
(@requestObject.spec.containers.securityContext.privileged:true
 OR @requestObject.spec.hostPID:true
 OR @requestObject.spec.hostNetwork:true)'''),

        ("kubectl exec sessions",
         "Live shells into running pods — operationally normal for engineers, anomalous in prod namespaces.",
         '''source:kubernetes.audit
@verb:create @objectRef.subresource:exec'''),

        ("Cluster-admin role bindings",
         "New bindings of high-privilege cluster roles — full-takeover risk.",
         '''source:kubernetes.audit
@verb:create
@objectRef.resource:(clusterrolebindings OR rolebindings)
@requestObject.roleRef.name:(cluster-admin OR admin OR edit)'''),
    ],

    "okta": [
        ("All activity for a user",
         "User triage — every Okta event tied to one identity. Replace `<email>`.",
         '''source:okta @actor.alternateId:<email>'''),

        ("All activity from one source IP",
         "IP pivot — every account touched from this address. Replace `<IP>`.",
         '''source:okta @client.ipAddress:<IP>'''),

        ("Authentication failures",
         "All failed sign-ins.",
         '''source:okta @evt.name:user.session.start @outcome.result:FAILURE'''),

        ("Account lockouts",
         "user.account.lock — pair with @client.ipAddress to see lockout sources.",
         '''source:okta @evt.name:user.account.lock'''),

        ("MFA factor enrolment / reset",
         "New MFA factor or factor reset — adversary persistence path.",
         '''source:okta @evt.name:(user.mfa.factor.activate OR user.mfa.factor.reset_all OR user.mfa.factor.deactivate)'''),

        ("Admin privilege grants",
         "Direct grants of Okta admin roles to a user — anomalous outside scim/automation.",
         '''source:okta @evt.name:user.account.privilege.grant'''),
    ],

    "slack": [
        ("All activity for a user",
         "User triage — every Slack event tied to one identity. Replace `<email>`.",
         '''source:slack @actor.user.email:<email>'''),

        ("File downloads from external workspaces",
         "Cross-workspace file lift — external collaboration risk.",
         '''source:slack @evt.name:file_downloaded
@actor.user.team:<external-team-id>'''),

        ("App / integration installed",
         "New third-party Slack app — pivot for OAuth-scope review.",
         '''source:slack @evt.name:app_installed'''),

        ("Channel made public",
         "Private channel flipped to public.",
         '''source:slack @evt.name:public_channel_created
OR (@evt.name:channel_settings_updated @change.field:visibility @change.new:public)'''),
    ],

    "microsoft.teams": [
        ("All Teams activity for a user",
         "User triage. Replace `<upn>`.",
         '''source:microsoft.teams @user.userPrincipalName:<upn>'''),

        ("External user added to a team",
         "Guest-user invite — pivot for org-policy enforcement.",
         '''source:microsoft.teams @evt.name:MemberAdded
@user.userPrincipalName:*#EXT#*'''),

        ("Teams app installed in a tenant",
         "New tenant-wide app installation. Replace `<appName>` if scoping.",
         '''source:microsoft.teams @evt.name:AppInstalled'''),

        ("Federated chat with external organisation",
         "External-tenant chat session — guest collaboration / data-leak risk.",
         '''source:microsoft.teams @evt.name:MessageSent
@chat.chatType:meetingChat OR @chat.chatType:oneOnOne
@user.userPrincipalName:*#EXT#*'''),
    ],

    "salesforce": [
        ("All activity for a user",
         "User triage. Replace `<username>`.",
         '''source:salesforce @usr.username:<username>'''),

        ("Mass record export (Data Loader / report export)",
         "Bulk-export pattern — credential / data exfil indicator.",
         '''source:salesforce
@evt.name:(REPORT_EXPORT OR DATA_EXPORT OR BULK_API)'''),

        ("Login from a new IP",
         "Pivot for credential-stuffing or impossible-travel hunts.",
         '''source:salesforce @evt.name:Login @status:Success
@network.client.ip:*'''),

        ("Permission set assignment",
         "Privilege drift in Salesforce — user gets new permissions.",
         '''source:salesforce @evt.name:PermissionSetAssignment'''),
    ],
}


# =============================================================================
# Render
# =============================================================================

# Splunk SPL summarised/non-summarised conversion. Mirrors the helpers in
# generate.py — duplicated locally so build_soc_cheatsheet.py stays fast at
# import time (no need to load the full pipeline catalog just to render a
# cheat sheet).
import re as _re_spl


def _spl_make_unsummarised(spl: str) -> str:
    if not spl or "tstats" not in spl.lower():
        return spl
    out = spl
    out = _re_spl.sub(r"`summariesonly`", "summariesonly=false", out)
    out = _re_spl.sub(r"\bsummariesonly\s*=\s*(?:true|t|1|yes|y)\b",
                       "summariesonly=false", out, flags=_re_spl.IGNORECASE)
    if not _re_spl.search(r"\bsummariesonly\s*=", out, flags=_re_spl.IGNORECASE):
        out = _re_spl.sub(r"(\|\s*tstats\b)(\s+)",
                            r"\1 summariesonly=false\2", out, count=1,
                            flags=_re_spl.IGNORECASE)
    return out


def _spl_has_dual_form(spl: str) -> bool:
    return bool(spl) and _spl_make_unsummarised(spl) != spl


def render_query(q: tuple[str, str, str], i: int) -> str:
    title, desc, body = q
    # Splunk SPL queries that use the `summariesonly` macro / tstats get a
    # nested Summarised / Non-summarised toggle so analysts on non-CIM-
    # accelerated environments can flip to the working variant inline.
    if _spl_has_dual_form(body):
        alt = _spl_make_unsummarised(body)
        block = f"""
      <div class="kql-block spl-toggle-group">
        <div class="spl-mode-toggle">
          <button class="spl-mode-btn active" data-spl-mode="acc" data-target="q-{i}-acc">Summarised</button>
          <button class="spl-mode-btn" data-spl-mode="raw" data-target="q-{i}-raw">Non-summarised</button>
          <span class="spl-mode-hint">Toggle if your env has no CIM data-model acceleration.</span>
        </div>
        <button class="copy" type="button" title="Copy to clipboard">Copy</button>
        <pre class="spl-mode-body active" id="q-{i}-acc"><code>{html.escape(body)}</code></pre>
        <pre class="spl-mode-body" id="q-{i}-raw"><code>{html.escape(alt)}</code></pre>
      </div>"""
    else:
        block = f"""
      <div class="kql-block">
        <button class="copy" type="button" title="Copy to clipboard">Copy</button>
        <pre><code>{html.escape(body)}</code></pre>
      </div>"""
    return f"""
    <article class="query" id="q-{i}">
      <header>
        <h4>{html.escape(title)}</h4>
        <p>{html.escape(desc)}</p>
      </header>{block}
    </article>
"""


def render_table_section(table: str, queries: list, columns: list[str],
                          id_prefix: str = "table-") -> str:
    items = "\n".join(render_query(q, idx) for idx, q in enumerate(queries))
    cols_html = " · ".join(f"<code>{html.escape(c)}</code>" for c in columns)
    return f"""
<section class="table-section" id="{id_prefix}{table}" data-table="{table}">
  <header class="table-header">
    <h2>{html.escape(table)}</h2>
    <p class="muted">{len(columns)} columns · {len(queries)} queries</p>
    <details class="schema">
      <summary>Schema (click to expand)</summary>
      <p class="cols">{cols_html}</p>
    </details>
  </header>
  {items}
</section>
"""


def render_sidebar(tables_with_counts: list[tuple[str, int]],
                   list_id: str, filter_id: str, id_prefix: str = "table-") -> str:
    items = "\n".join(
        f'<li><a href="#{id_prefix}{t}" data-table="{t}"><span class="t">{html.escape(t)}</span><span class="n">{n}</span></a></li>'
        for t, n in tables_with_counts
    )
    return f"""
<nav class="cs-sidebar">
  <input type="search" id="{filter_id}" placeholder="Filter tables…" autocomplete="off">
  <ul id="{list_id}">
    {items}
  </ul>
</nav>
"""


def _build_pane(queries: dict, schema: dict, id_prefix: str,
                list_id: str, filter_id: str) -> tuple[str, str, int, int, int]:
    """Render the sidebar + section blocks for one platform.

    `id_prefix` namespaces the section IDs so duplicate table names across
    platforms (IdentityInfo, DeviceInfo) don't produce colliding HTML IDs.
    """
    ordered = list(queries.keys())
    leftovers = sorted(t for t in schema if not t.startswith("_") and t not in queries
                       and isinstance(schema.get(t), list))
    sidebar_data = [(t, len(queries.get(t, []))) for t in ordered + leftovers]

    sections = []
    for t in ordered:
        cols = schema.get(t, [])
        sections.append(render_table_section(t, queries[t], cols, id_prefix=id_prefix))
    for t in leftovers:
        cols = schema.get(t, [])
        sections.append(f"""
<section class="table-section" id="{id_prefix}{t}" data-table="{t}">
  <header class="table-header">
    <h2>{html.escape(t)}</h2>
    <p class="muted">{len(cols)} columns · 0 queries (curation pending)</p>
    <p class="cols">{" · ".join(f'<code>{html.escape(c)}</code>' for c in cols)}</p>
  </header>
</section>
""")

    return (
        render_sidebar(sidebar_data, list_id=list_id, filter_id=filter_id, id_prefix=id_prefix),
        "\n".join(sections),
        len(queries),
        sum(len(v) for v in queries.values()),
        len(sidebar_data),
    )


# =============================================================================
# Sigma — load rules from sigma_rules/, pre-compile to common backends.
# =============================================================================

SIGMA_RULES_DIR = ROOT / "sigma_rules"


def _load_sigma_rules() -> list[dict]:
    """Read every YAML under sigma_rules/, parse, pre-compile to KQL+SPL+Lucene.

    Each entry is {file, kill_chain, parsed (dict), yaml (str), kql, spl,
    lucene, errors}. Compile failures are recorded but never fatal.
    """
    rules: list[dict] = []
    if not SIGMA_RULES_DIR.exists():
        return rules
    try:
        # Side-imports so the cheat sheet can build without pysigma when
        # the user explicitly skipped the optional dependency.
        from sigma_export import compile_sigma, validate_sigma
    except Exception as e:
        print(f"  [!] sigma_export unavailable ({e}); skipping Sigma tab.")
        return rules

    import yaml as _yaml
    for path in sorted(SIGMA_RULES_DIR.rglob("*.yml")):
        text = path.read_text(encoding="utf-8")
        try:
            parsed = _yaml.safe_load(text)
        except Exception:
            parsed = {}
        kill_chain = path.parent.name  # actions / c2 / delivery / etc.
        v_issues = validate_sigma(text)
        compiled: dict[str, str | None] = {}
        for tag in ("kql", "spl", "lucene"):
            out, err = compile_sigma(text, tag)
            compiled[tag] = out if not err else f"// compile error: {err}"
        rules.append({
            "path": path.relative_to(ROOT).as_posix(),
            "filename": path.stem,
            "kill_chain": kill_chain,
            "parsed": parsed if isinstance(parsed, dict) else {},
            "yaml": text,
            "kql": compiled["kql"],
            "spl": compiled["spl"],
            "lucene": compiled["lucene"],
            "validation_issues": v_issues,
        })
    return rules


def render_sigma_card(rule: dict, idx: int) -> str:
    title = html.escape(rule["parsed"].get("title", rule["filename"]))
    desc = html.escape((rule["parsed"].get("description") or "").strip())
    level = html.escape(rule["parsed"].get("level", ""))
    tags = rule["parsed"].get("tags", []) or []
    logsource = rule["parsed"].get("logsource", {}) or {}
    ls_str = " · ".join(f"{k}={v}" for k, v in logsource.items() if v)
    tag_html = " ".join(
        f'<span class="sigma-tag">{html.escape(str(t))}</span>' for t in tags[:8]
    )
    uid = f"sigma-{idx}"
    return f"""
<article class="sigma-rule" id="{uid}" data-killchain="{html.escape(rule['kill_chain'])}">
  <header>
    <div class="sigma-title-row">
      <h4>{title}</h4>
      <span class="sigma-level lvl-{level}">{level or 'unknown'}</span>
    </div>
    <p class="muted">{desc}</p>
    <p class="sigma-meta">
      <code>{html.escape(ls_str)}</code> · <code>{html.escape(rule['path'])}</code>
    </p>
    <div class="sigma-tags">{tag_html}</div>
  </header>
  <div class="sigma-tabs">
    <button class="sigma-tab active" data-target="{uid}-yaml">Sigma YAML</button>
    <button class="sigma-tab" data-target="{uid}-kql">Defender KQL</button>
    <button class="sigma-tab" data-target="{uid}-spl">Splunk SPL</button>
    <button class="sigma-tab" data-target="{uid}-lucene">Elastic Lucene</button>
  </div>
  <div class="sigma-pane active" id="{uid}-yaml">
    <button class="copy" type="button">Copy</button>
    <pre><code>{html.escape(rule['yaml'])}</code></pre>
  </div>
  <div class="sigma-pane" id="{uid}-kql">
    <button class="copy" type="button">Copy</button>
    <pre><code>{html.escape(rule['kql'] or '(no output)')}</code></pre>
  </div>
  <div class="sigma-pane" id="{uid}-spl">
    <button class="copy" type="button">Copy</button>
    <pre><code>{html.escape(rule['spl'] or '(no output)')}</code></pre>
  </div>
  <div class="sigma-pane" id="{uid}-lucene">
    <button class="copy" type="button">Copy</button>
    <pre><code>{html.escape(rule['lucene'] or '(no output)')}</code></pre>
  </div>
</article>
"""


def render_sigma_pane(rules: list[dict]) -> tuple[str, int]:
    if not rules:
        return ('<div class="placeholder-pane"><h2>No Sigma rules found</h2>'
                '<p>Add rules to <code>sigma_rules/</code>, then re-run '
                '<code>python build_soc_cheatsheet.py</code>.</p></div>', 0)
    by_kc: dict[str, list[dict]] = {}
    for r in rules:
        by_kc.setdefault(r["kill_chain"], []).append(r)
    sections = []
    idx = 0
    for kc in sorted(by_kc):
        cards = []
        for r in by_kc[kc]:
            cards.append(render_sigma_card(r, idx))
            idx += 1
        sections.append(
            f'<section class="sigma-section">'
            f'<h2>{html.escape(kc)}</h2>'
            f'<p class="muted">{len(by_kc[kc])} rules · platform-neutral, compiled at build time</p>'
            f'{"".join(cards)}'
            f'</section>'
        )
    return "\n".join(sections), len(rules)


def main() -> None:
    (kql_sidebar, kql_sections,
     kql_curated, kql_total_q, kql_schema_tables) = _build_pane(
        QUERIES, SCHEMA, id_prefix="kql-table-",
        list_id="tableList", filter_id="tableFilter")

    (sent_sidebar, sent_sections,
     sent_curated, sent_total_q, sent_schema_tables) = _build_pane(
        SENTINEL_QUERIES, SENTINEL_SCHEMA, id_prefix="sentinel-table-",
        list_id="sentinelTableList", filter_id="sentinelTableFilter")

    # Datadog Cloud SIEM uses log-source names in place of table names. The
    # _build_pane helper is shape-agnostic — we pass DATADOG_SOURCES as the
    # "schema" so the analyst sees attribute paths in the schema-collapse
    # under each source heading.
    (ddog_sidebar, ddog_sections,
     ddog_curated, ddog_total_q, ddog_schema_tables) = _build_pane(
        DATADOG_QUERIES, DATADOG_SOURCES, id_prefix="datadog-source-",
        list_id="datadogSourceList", filter_id="datadogSourceFilter")

    # Splunk SPL — CIM datamodels in place of tables.
    (spl_sidebar, spl_sections,
     spl_curated, spl_total_q, spl_schema_tables) = _build_pane(
        SPLUNK_QUERIES, SPLUNK_DATAMODELS, id_prefix="spl-dm-",
        list_id="splunkDmList", filter_id="splunkDmFilter")

    sigma_rules = _load_sigma_rules()
    sigma_sections, sigma_count = render_sigma_pane(sigma_rules)

    OUT.write_text(_TEMPLATE.format(
        kql_sidebar=kql_sidebar,
        kql_sections=kql_sections,
        kql_curated=kql_curated,
        kql_total_q=kql_total_q,
        kql_schema_tables=kql_schema_tables,
        sent_sidebar=sent_sidebar,
        sent_sections=sent_sections,
        sent_curated=sent_curated,
        sent_total_q=sent_total_q,
        sent_schema_tables=sent_schema_tables,
        ddog_sidebar=ddog_sidebar,
        ddog_sections=ddog_sections,
        ddog_curated=ddog_curated,
        ddog_total_q=ddog_total_q,
        ddog_schema_tables=ddog_schema_tables,
        spl_sidebar=spl_sidebar,
        spl_sections=spl_sections,
        spl_curated=spl_curated,
        spl_total_q=spl_total_q,
        spl_schema_tables=spl_schema_tables,
        sigma_sections=sigma_sections,
        sigma_count=sigma_count,
    ), encoding="utf-8")
    print(f"Wrote {OUT.relative_to(ROOT)}")
    print(f"  Defender:  {kql_curated} curated tables, {kql_total_q} queries "
          f"(across {kql_schema_tables} schema tables)")
    print(f"  Sentinel:  {sent_curated} curated tables, {sent_total_q} queries "
          f"(across {sent_schema_tables} schema tables)")
    print(f"  Datadog:   {ddog_curated} curated sources, {ddog_total_q} queries "
          f"(across {ddog_schema_tables} sources)")
    print(f"  Splunk:    {spl_curated} curated CIM datamodels, {spl_total_q} queries "
          f"(across {spl_schema_tables} datamodels)")
    print(f"  Sigma:     {sigma_count} rules pre-compiled (KQL/SPL/Lucene each)")


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Analyst Cheat Sheet — KQL · Clankerusecase</title>
<link rel="icon" type="image/png" href="logo.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{
  --bg:#08090a; --panel:#16171b; --panel-elev:#1f2024; --panel2:#26272b;
  --text:#f7f8f8; --muted:#8a8f98; --muted-2:#62656a;
  --accent:#7170ff; --accent-2:#9b8afb; --good:#4cb782; --warn:#e2a93f;
  --border:rgba(255,255,255,0.07); --border-2:rgba(255,255,255,0.12);
  --code-bg:#1a1b1e;
  --r-sm:4px; --r-md:6px; --r-lg:8px;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
}}
*{{box-sizing:border-box}}
html,body{{margin:0;height:100%}}
body{{
  background:radial-gradient(1200px 500px at 50% -10%,rgba(113,112,255,0.06),transparent 60%),var(--bg);
  background-attachment:fixed;color:var(--text);
  font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  font-size:13.5px;line-height:1.55;letter-spacing:-0.003em;
  -webkit-font-smoothing:antialiased;
}}
::selection{{background:rgba(113,112,255,0.32);color:#fff}}
a{{color:inherit;text-decoration:none}}

/* Top bar */
.cs-topbar{{
  position:sticky;top:0;z-index:50;
  background:rgba(8,9,10,0.78);backdrop-filter:blur(16px) saturate(160%);
  border-bottom:1px solid var(--border);
  padding:14px 28px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;
}}
.cs-brand{{display:flex;align-items:center;gap:12px;font-weight:600;font-size:18px;letter-spacing:-0.018em}}
.cs-brand img{{width:36px;height:36px;border-radius:8px;border:1px solid var(--border-2)}}
.cs-brand .sub{{color:var(--muted);font-weight:500;font-size:12px}}
.cs-back{{margin-left:auto;color:var(--muted);font-size:12.5px;border:1px solid var(--border);padding:6px 12px;border-radius:var(--r-sm);transition:all .15s}}
.cs-back:hover{{color:var(--text);border-color:var(--border-2);background:var(--panel)}}

/* Platform tabs */
.cs-tabs{{
  border-bottom:1px solid var(--border);padding:0 28px;
  background:rgba(8,9,10,0.45);backdrop-filter:blur(8px);
  display:flex;gap:4px;align-items:flex-end;
}}
.cs-tab{{
  background:transparent;color:var(--muted);border:0;border-bottom:2px solid transparent;
  font:inherit;padding:10px 16px;cursor:pointer;font-weight:500;
  letter-spacing:-0.005em;transition:all .15s;
}}
.cs-tab:hover{{color:var(--text)}}
.cs-tab.active{{color:var(--text);border-bottom-color:var(--accent)}}
.cs-tab .badge{{margin-left:6px;font-size:10.5px;padding:1px 6px;border-radius:99px;background:rgba(113,112,255,0.12);color:var(--accent-2);border:1px solid rgba(113,112,255,0.20)}}
.cs-tab.placeholder .badge{{background:rgba(226,169,63,0.12);color:var(--warn);border-color:rgba(226,169,63,0.30)}}

/* Layout */
.cs-layout{{display:grid;grid-template-columns:280px 1fr;min-height:calc(100vh - 110px)}}
.cs-sidebar{{
  border-right:1px solid var(--border);padding:18px;
  position:sticky;top:110px;align-self:start;
  height:calc(100vh - 110px);overflow-y:auto;
}}
.cs-sidebar input[type=search]{{
  width:100%;background:var(--panel);color:var(--text);border:1px solid var(--border);
  border-radius:var(--r-sm);padding:7px 10px;font:inherit;font-size:12.5px;
  margin-bottom:10px;
}}
.cs-sidebar input[type=search]:focus{{outline:0;border-color:var(--accent);box-shadow:0 0 0 3px rgba(113,112,255,0.18)}}
.cs-sidebar ul{{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:1px}}
.cs-sidebar li a{{
  display:flex;justify-content:space-between;align-items:center;
  padding:6px 10px;border-radius:var(--r-sm);color:var(--muted);font-size:12.5px;
  font-family:var(--mono);letter-spacing:-0.005em;
}}
.cs-sidebar li a:hover{{background:var(--panel);color:var(--text)}}
.cs-sidebar li a.active{{background:rgba(113,112,255,0.10);color:var(--accent-2);border-left:2px solid var(--accent);padding-left:8px}}
.cs-sidebar li a .n{{color:var(--muted-2);font-size:11px;padding:0 6px;border-radius:99px;background:var(--panel-elev);border:1px solid var(--border)}}

.cs-main{{padding:28px;max-width:1080px}}
.cs-intro{{margin-bottom:24px;padding:16px;border:1px solid var(--border);border-radius:var(--r-md);background:var(--panel)}}
.cs-intro h1{{margin:0 0 4px;font-size:18px;font-weight:600;letter-spacing:-0.020em}}
.cs-intro p{{margin:0;color:var(--muted);font-size:12.5px}}
.cs-intro .stats{{display:flex;gap:18px;margin-top:10px;font-size:12px}}
.cs-intro .stats span strong{{color:var(--text);font-weight:600}}
.cs-intro .stats span{{color:var(--muted)}}

.placeholder-pane{{padding:48px 24px;border:1px dashed var(--border-2);border-radius:var(--r-md);background:var(--panel);text-align:center;color:var(--muted)}}
.placeholder-pane h2{{color:var(--text);font-weight:600;font-size:18px;margin:0 0 8px;letter-spacing:-0.018em}}
.placeholder-pane code{{background:var(--code-bg);border:1px solid var(--border);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:11.5px;color:var(--accent-2)}}

/* Table sections */
.table-section{{margin-bottom:48px;scroll-margin-top:130px}}
.table-header{{margin-bottom:14px}}
.table-header h2{{margin:0;font-size:22px;font-weight:600;letter-spacing:-0.022em;color:var(--text);font-family:var(--mono)}}
.table-header .muted{{color:var(--muted);margin:2px 0 8px;font-size:12px}}
.table-header details{{margin-top:6px;font-size:12px}}
.table-header summary{{cursor:pointer;color:var(--accent-2);user-select:none}}
.table-header .cols{{margin:8px 0 0;color:var(--muted);font-size:11.5px;line-height:1.8}}
.table-header .cols code{{background:var(--code-bg);border:1px solid var(--border);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:10.5px;color:var(--text)}}

/* Query cards */
.query{{
  background:var(--panel);border:1px solid var(--border);border-radius:var(--r-md);
  margin-bottom:14px;
}}
.query > header{{padding:14px 18px;border-bottom:1px solid var(--border)}}
.query h4{{margin:0 0 4px;font-size:13.5px;font-weight:600;letter-spacing:-0.012em}}
.query > header p{{margin:0;color:var(--muted);font-size:12.2px}}
.kql-block{{position:relative}}
.kql-block pre{{
  margin:0;padding:14px 18px;overflow-x:auto;
  font-family:var(--mono);font-size:12px;line-height:1.55;color:var(--text);
  background:var(--code-bg);border-radius:0 0 var(--r-md) var(--r-md);
}}
.kql-block code{{font-family:var(--mono);white-space:pre;color:var(--text)}}
.copy{{
  position:absolute;top:8px;right:8px;
  background:rgba(255,255,255,0.06);color:var(--muted);
  border:1px solid var(--border-2);font:inherit;font-size:11px;
  padding:4px 10px;border-radius:var(--r-sm);cursor:pointer;
  transition:all .15s;font-family:var(--mono);
}}
.copy:hover{{color:var(--text);background:rgba(255,255,255,0.10);border-color:var(--accent)}}
.copy.copied{{color:var(--good);border-color:rgba(76,183,130,0.45)}}

/* Tab pane visibility */
.tab-pane{{display:none}}
.tab-pane.active{{display:block}}

/* ------ Sigma cards ------------------------------------------------- */
.sigma-section{{margin-bottom:48px;scroll-margin-top:130px}}
.sigma-section > h2{{margin:0 0 4px;font-size:18px;font-weight:600;letter-spacing:-0.018em;text-transform:capitalize;color:var(--text)}}
.sigma-section > p.muted{{color:var(--muted);font-size:12px;margin:0 0 14px}}
.sigma-rule{{background:var(--panel);border:1px solid var(--border);border-radius:var(--r-md);margin-bottom:14px}}
.sigma-rule > header{{padding:14px 18px;border-bottom:1px solid var(--border)}}
.sigma-title-row{{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:4px}}
.sigma-rule h4{{margin:0;font-size:13.5px;font-weight:600;letter-spacing:-0.012em}}
.sigma-rule p{{margin:0;color:var(--muted);font-size:12.2px}}
.sigma-rule .sigma-meta{{margin-top:4px;font-size:11.5px}}
.sigma-rule .sigma-meta code{{background:var(--code-bg);border:1px solid var(--border);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:11px;color:var(--accent-2)}}
.sigma-tags{{margin-top:6px;display:flex;flex-wrap:wrap;gap:4px}}
.sigma-tag{{font-family:var(--mono);font-size:10.5px;padding:2px 7px;border-radius:99px;background:rgba(155,138,251,0.10);color:var(--accent-2);border:1px solid rgba(155,138,251,0.20)}}
.sigma-level{{font-family:var(--mono);font-size:10.5px;padding:3px 9px;border-radius:99px;text-transform:uppercase;letter-spacing:0.04em;font-weight:600}}
.sigma-level.lvl-low{{background:rgba(76,183,130,0.10);color:var(--good);border:1px solid rgba(76,183,130,0.30)}}
.sigma-level.lvl-medium{{background:rgba(226,169,63,0.10);color:var(--warn);border:1px solid rgba(226,169,63,0.30)}}
.sigma-level.lvl-high{{background:rgba(235,87,87,0.10);color:#eb5757;border:1px solid rgba(235,87,87,0.30)}}
.sigma-level.lvl-critical{{background:rgba(242,85,85,0.16);color:#f25555;border:1px solid rgba(242,85,85,0.40)}}
.sigma-tabs{{display:flex;gap:2px;padding:8px 14px 0;background:rgba(255,255,255,0.02);border-bottom:1px solid var(--border)}}
.sigma-tab{{background:transparent;color:var(--muted);border:0;border-bottom:2px solid transparent;font:inherit;font-size:11.5px;padding:6px 10px;cursor:pointer;font-weight:500;transition:all 0.15s;font-family:var(--mono)}}
.sigma-tab:hover{{color:var(--text)}}
.sigma-tab.active{{color:var(--accent-2);border-bottom-color:var(--accent)}}
.sigma-pane{{display:none;position:relative}}
.sigma-pane.active{{display:block}}
.sigma-pane pre{{margin:0;padding:14px 18px;overflow-x:auto;font-family:var(--mono);font-size:11.5px;line-height:1.55;background:var(--code-bg);border-radius:0 0 var(--r-md) var(--r-md)}}

/* Splunk SPL Summarised / Non-summarised toggle (mirrors generate.py's
   article-card pattern). Wraps in .spl-toggle-group so the click handler
   can scope to one query at a time. */
.spl-toggle-group{{position:relative}}
.spl-mode-toggle{{
  display:flex;gap:4px;align-items:center;flex-wrap:wrap;
  padding:6px 10px;
  background:rgba(255,255,255,0.03);
  border-radius:var(--r-sm) var(--r-sm) 0 0;
  border-bottom:1px solid var(--border);
}}
.spl-mode-btn{{
  background:transparent;border:0;color:var(--muted);
  padding:4px 10px;border-radius:4px;cursor:pointer;
  font:inherit;font-size:11px;font-weight:500;
  transition:color 0.12s,background 0.12s;
}}
.spl-mode-btn:hover{{color:var(--text)}}
.spl-mode-btn.active{{
  background:rgba(113,112,255,0.16);color:var(--text);
}}
.spl-mode-hint{{font-size:10.5px;color:var(--muted-2);margin-left:8px}}
.spl-mode-body{{display:none}}
.spl-mode-body.active{{display:block}}

/* Mobile */
@media (max-width: 900px) {{
  .cs-layout{{grid-template-columns:1fr}}
  .cs-sidebar{{position:relative;top:0;height:auto;max-height:50vh;border-right:0;border-bottom:1px solid var(--border)}}
}}
</style>
</head>
<body>

<header class="cs-topbar">
  <div class="cs-brand">
    <img src="logo.png" alt="">
    <div>
      <div>SOC Analyst Cheat Sheet</div>
      <div class="sub">Hand-curated queries · Clankerusecase</div>
    </div>
  </div>
  <a href="index.html" class="cs-back">← Back to main site</a>
</header>

<nav class="cs-tabs">
  <button class="cs-tab active" data-pane="kql">KQL <span class="badge">Defender XDR</span></button>
  <button class="cs-tab" data-pane="sentinel">KQL <span class="badge">Sentinel</span></button>
  <button class="cs-tab" data-pane="datadog">Datadog <span class="badge">Cloud SIEM</span></button>
  <button class="cs-tab" data-pane="spl">SPL <span class="badge">Splunk · CIM</span></button>
  <button class="cs-tab" data-pane="sigma">Sigma <span class="badge">Platform-neutral</span></button>
</nav>

<div id="pane-kql" class="tab-pane active">
  <div class="cs-layout">
    {kql_sidebar}
    <main class="cs-main">
      <div class="cs-intro">
        <h1>Microsoft 365 Defender · Advanced Hunting</h1>
        <p>Pick a table from the sidebar (or scroll) — every query is schema-validated against the canonical column list and follows the BluRaven house style: time-bound first (<code>Timestamp</code>), machine-account excluded, case-insensitive equality, indexed token matching.</p>
        <div class="stats">
          <span><strong>{kql_curated}</strong> tables curated</span>
          <span><strong>{kql_total_q}</strong> queries</span>
          <span><strong>{kql_schema_tables}</strong> schema tables</span>
          <span>Click <strong>Copy</strong> on any query to paste into Defender Advanced Hunting.</span>
        </div>
      </div>

      {kql_sections}
    </main>
  </div>
</div>

<div id="pane-sentinel" class="tab-pane">
  <div class="cs-layout">
    {sent_sidebar}
    <main class="cs-main">
      <div class="cs-intro">
        <h1>Microsoft Sentinel · KQL Search</h1>
        <p>Sentinel speaks the same KQL but on a different schema — <code>TimeGenerated</code> instead of <code>Timestamp</code>, <code>SecurityEvent</code>/<code>SigninLogs</code>/<code>OfficeActivity</code>/<code>ASIM Im*</code> instead of the Defender <code>Device*</code> tables. Every query below is schema-validated against the canonical Sentinel column list.</p>
        <div class="stats">
          <span><strong>{sent_curated}</strong> tables curated</span>
          <span><strong>{sent_total_q}</strong> queries</span>
          <span><strong>{sent_schema_tables}</strong> schema tables</span>
          <span>Click <strong>Copy</strong> on any query to paste into Log Analytics / Sentinel.</span>
        </div>
      </div>

      {sent_sections}
    </main>
  </div>
</div>

<div id="pane-datadog" class="tab-pane">
  <div class="cs-layout">
    {ddog_sidebar}
    <main class="cs-main">
      <div class="cs-intro">
        <h1>Datadog · Cloud SIEM logs query</h1>
        <p>Pick a log source from the sidebar — every query is verbatim Datadog Logs Explorer / Cloud SIEM syntax: <code>source:</code> first, <code>@field.path:value</code> filters, uppercase boolean operators, <code>CIDR(@ip, range)</code> for IP filtering. Time windows are configured at rule level in Datadog so they're absent from the query body.</p>
        <p style="background:rgba(113,112,255,0.06);border:1px solid rgba(113,112,255,0.20);border-radius:var(--r-md);padding:8px 14px;margin:10px 0 12px 0;font-size:12.5px;">
          <strong>Reference Tables</strong> let you maintain large IOC / known-bad / allowlist tables in Datadog and pivot via them in queries — handy for IP-block / hash-list / domain-list filters that grow over time. Syntax: <code>CIDR(@network.client.ip, *RefTable:bad_ips_v2*)</code> or <code>@process.name IN *RefTable:lolbins*</code>. Build / upload tables under <em>Logs → Configuration → Reference Tables</em>; queries below use literal lists for clarity but swap in a Reference Table any time a list grows past ~100 entries.
        </p>
        <div class="stats">
          <span><strong>{ddog_curated}</strong> sources curated</span>
          <span><strong>{ddog_total_q}</strong> queries</span>
          <span>Click <strong>Copy</strong> on any query to paste into Datadog Logs / Cloud SIEM rule editor.</span>
        </div>
      </div>

      {ddog_sections}
    </main>
  </div>
</div>

<div id="pane-sigma" class="tab-pane">
  <main class="cs-main">
    <div class="cs-intro">
      <h1>Sigma · platform-neutral detection rules</h1>
      <p>Sigma is a generic, YAML-based signature format for SIEM detections. Each rule below is a self-contained Sigma YAML, pre-compiled to Defender KQL, Splunk SPL, and Elastic Lucene at build time — copy whichever format your SIEM speaks. Source rules live under <code>sigma_rules/</code>; re-run <code>python build_soc_cheatsheet.py</code> after editing to refresh.</p>

      <details style="background:rgba(113,112,255,0.06);border:1px solid rgba(113,112,255,0.20);border-radius:var(--r-md);padding:10px 14px;margin:12px 0 14px 0;font-size:12.5px;line-height:1.6;">
        <summary style="cursor:pointer;font-weight:600;color:var(--accent-2);font-size:13px;">Sigma syntax cheat sheet — click to expand</summary>
        <p style="margin-top:10px;"><strong>Top-level fields</strong>:</p>
        <pre style="font-size:11.5px;background:var(--code-bg);padding:10px;border-radius:var(--r-sm);overflow-x:auto;"><code>title:        # Short, descriptive
id:           # UUID — gives the rule a stable identity
status:       # stable | test | experimental | deprecated | unsupported
description:  # 1-3 sentences on what it catches
references:   # URLs to relevant intel / vendor advisories
author:       # Free-form
date:         # 2026/05/07
tags:         # attack.t1059, attack.execution, etc — MITRE ATT&amp;CK
logsource:    # Where the rule applies
  product:    #   windows / linux / macos / aws / azure / etc
  service:    #   security / sysmon / cloudtrail / ...
  category:   #   process_creation / file_event / network_connection / ...
detection:    # The actual matching logic
  selection:  #   Match condition — ANDed by default within a block
  filter:     #   Optional — fields to exclude
  condition:  # selection and not filter / 1 of selection_* / etc.
falsepositives: [...]
level:        # informational | low | medium | high | critical</code></pre>
        <p><strong>Field modifiers</strong> (suffix after the field name):</p>
        <ul style="margin:6px 0 0 18px;padding:0;">
          <li><code>field|contains: value</code> — substring match</li>
          <li><code>field|startswith: value</code> / <code>|endswith: value</code></li>
          <li><code>field|re: regex</code> — Sigma regex (PCRE-flavoured)</li>
          <li><code>field|all: [a, b]</code> — list AND (must contain all)</li>
          <li><code>field|cased</code> — case-sensitive (default is case-insensitive)</li>
          <li><code>field|windash</code> — accept either <code>-</code> or <code>/</code> as the prefix to a Windows-style flag (e.g. <code>-encodedcommand</code> or <code>/encodedcommand</code>)</li>
          <li><code>field|expand</code> — expand placeholders defined under <code>placeholders:</code></li>
        </ul>
        <p style="margin-top:10px;"><strong>Compilation cheat sheet</strong> — what each Sigma construct becomes:</p>
        <ul style="margin:6px 0 0 18px;padding:0;">
          <li><code>field|contains: x</code> → KQL <code>field has "x"</code> · SPL <code>field="*x*"</code> · Lucene <code>field:*x*</code></li>
          <li><code>field|startswith: x</code> → KQL <code>field startswith "x"</code> · SPL <code>field="x*"</code> · Lucene <code>field:x*</code></li>
          <li><code>field: [a, b, c]</code> → KQL <code>field in ("a","b","c")</code> · SPL <code>field IN ("a","b","c")</code></li>
          <li><code>condition: 1 of selection_*</code> → OR across every block whose name matches</li>
          <li><code>condition: all of selection_*</code> → AND across every matching block</li>
          <li><code>timeframe: 5m</code> + aggregation — only some backends support; Splunk does, Defender doesn't</li>
        </ul>
        <p style="margin-top:10px;"><strong>When Sigma is the right tool</strong>: single-event-shape detections (one log line matches → fire). <strong>When it isn't</strong>: multi-stage temporal correlation, threshold-over-window aggregations, joins across data sources — those don't compile cleanly to all backends. Author those directly in KQL or SPL instead.</p>
        <p style="margin:10px 0 0 0;"><strong>Reference</strong>: <a href="https://github.com/SigmaHQ/sigma" style="color:var(--accent-2);">SigmaHQ/sigma</a> — the canonical rule repo + the latest spec.</p>
      </details>

      <div class="stats">
        <span><strong>{sigma_count}</strong> rules</span>
        <span>3 backends pre-compiled (KQL · SPL · Lucene)</span>
        <span>Add new rules to <code>sigma_rules/&lt;kill_chain&gt;/</code> and rebuild.</span>
      </div>
    </div>
    {sigma_sections}
  </main>
</div>

<div id="pane-spl" class="tab-pane">
  <div class="cs-layout">
    {spl_sidebar}
    <main class="cs-main">
      <div class="cs-intro">
        <h1>Splunk · CIM datamodels (SPL)</h1>
        <p>Pick a CIM datamodel from the sidebar — every query is verbatim Splunk SPL using <code>tstats</code> against accelerated datamodels. House style: <code>summariesonly</code> macro for fast tstats; <code>drop_dm_object_name(&lt;DM&gt;)</code> to flatten object-prefixed fields; <code>&lt;placeholder&gt;</code> fields the analyst replaces during a shift.</p>
        <p style="background:rgba(113,112,255,0.06);border:1px solid rgba(113,112,255,0.20);border-radius:var(--r-md);padding:10px 14px;margin:12px 0 14px 0;font-size:12.5px;line-height:1.55;">
          <strong>tstats vs <code>| from datamodel:</code> vs raw search.</strong>
          <code>tstats</code> queries against an accelerated CIM model are the fastest path — they read the precomputed summary index. If your env has no CIM acceleration, every tstats query below has a <strong>Non-summarised</strong> toggle that switches to <code>summariesonly=false</code> (slower but works without the summary). Raw <code>search index=...</code> queries always work but won't benefit from any acceleration.
        </p>
        <div class="stats">
          <span><strong>{spl_curated}</strong> CIM datamodels curated</span>
          <span><strong>{spl_total_q}</strong> queries</span>
          <span>Click <strong>Copy</strong> on any query to paste into Splunk Search.</span>
        </div>
      </div>

      {spl_sections}
    </main>
  </div>
</div>

<script>
(function () {{
  // Tab switching
  const tabs = document.querySelectorAll('.cs-tab');
  const panes = document.querySelectorAll('.tab-pane');
  tabs.forEach(tab => {{
    tab.addEventListener('click', () => {{
      const target = tab.dataset.pane;
      tabs.forEach(t => t.classList.toggle('active', t === tab));
      panes.forEach(p => p.classList.toggle('active', p.id === 'pane-' + target));
    }});
  }});

  // Copy buttons (works in any pane). When the query has a Summarised/
  // Non-summarised toggle, copy whichever variant is currently active.
  document.querySelectorAll('.copy').forEach(btn => {{
    btn.addEventListener('click', async () => {{
      const block = btn.closest('.kql-block, .spl-toggle-group') || btn.parentElement;
      const activeBody = block.querySelector('.spl-mode-body.active code');
      const fallback   = block.querySelector('code');
      const codeEl = activeBody || fallback;
      if (!codeEl) return;
      try {{
        await navigator.clipboard.writeText(codeEl.innerText);
        btn.classList.add('copied');
        const orig = btn.textContent;
        btn.textContent = '✓ Copied';
        setTimeout(() => {{ btn.textContent = orig; btn.classList.remove('copied'); }}, 1500);
      }} catch (e) {{
        btn.textContent = 'Copy failed';
      }}
    }});
  }});

  // Per-pane sidebar filter + scroll-active link highlighting.
  function bindSidebar(paneId, filterId, listId) {{
    const filter = document.getElementById(filterId);
    const items  = document.querySelectorAll('#' + listId + ' li');
    if (filter) {{
      filter.addEventListener('input', () => {{
        const q = filter.value.toLowerCase().trim();
        items.forEach(li => {{
          const t = li.querySelector('.t').textContent.toLowerCase();
          li.style.display = (!q || t.includes(q)) ? '' : 'none';
        }});
      }});
    }}
    const pane = document.getElementById(paneId);
    if (!pane) return;
    const sections = pane.querySelectorAll('.table-section');
    const links    = pane.querySelectorAll('#' + listId + ' a');
    const obs = new IntersectionObserver(entries => {{
      entries.forEach(e => {{
        if (!e.isIntersecting) return;
        const t = e.target.dataset.table;
        links.forEach(a => a.classList.toggle('active', a.dataset.table === t));
      }});
    }}, {{ rootMargin: '-30% 0px -60% 0px', threshold: 0 }});
    sections.forEach(s => obs.observe(s));
  }}
  bindSidebar('pane-kql',      'tableFilter',         'tableList');
  bindSidebar('pane-sentinel', 'sentinelTableFilter', 'sentinelTableList');
  bindSidebar('pane-datadog',  'datadogSourceFilter', 'datadogSourceList');
  bindSidebar('pane-spl',      'splunkDmFilter',      'splunkDmList');

  // Splunk SPL Summarised / Non-summarised toggle — same pattern as the
  // article-card surface: scoped via .spl-toggle-group so each query's
  // toggle is independent.
  document.addEventListener('click', e => {{
    const btn = e.target.closest('.spl-mode-btn');
    if (!btn) return;
    const parent = btn.closest('.spl-toggle-group');
    if (!parent) return;
    parent.querySelectorAll('.spl-mode-btn').forEach(b => b.classList.toggle('active', b === btn));
    parent.querySelectorAll('.spl-mode-body').forEach(p => {{
      p.classList.toggle('active', p.id === btn.dataset.target);
    }});
  }});

  // Make in-pane anchor links work even though both panes use `#table-X`
  // ids. Browser default ignores the second one because of the duplicate;
  // we fix this by scoping the scroll to the active pane.
  document.querySelectorAll('.cs-sidebar a').forEach(a => {{
    a.addEventListener('click', e => {{
      const id = a.getAttribute('href');
      if (!id || !id.startsWith('#')) return;
      const pane = a.closest('.tab-pane');
      if (!pane) return;
      const target = pane.querySelector(id);
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({{behavior:'smooth', block:'start'}});
    }});
  }});

  // Per-Sigma-card tab switching (yaml / kql / spl / lucene).
  document.querySelectorAll('.sigma-tab').forEach(btn => {{
    btn.addEventListener('click', () => {{
      const card = btn.closest('.sigma-rule');
      if (!card) return;
      const targetId = btn.dataset.target;
      card.querySelectorAll('.sigma-tab').forEach(t => t.classList.toggle('active', t === btn));
      card.querySelectorAll('.sigma-pane').forEach(p => p.classList.toggle('active', p.id === targetId));
    }});
  }});
}})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
