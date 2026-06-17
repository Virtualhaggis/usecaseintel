# [MED] Deno-Based RAT Uses Microsoft Teams Impersonation and Mailbombing to Target Employees

**Source:** Cyber Security News
**Published:** 2026-06-17
**Article:** https://cybersecuritynews.com/hackers-use-rokarolla-android-malware/

## Threat Profile

A new strain of malware has emerged that combines two well-known social engineering tactics into one effective attack chain. Researchers have uncovered a Remote Access Trojan built on Deno, an unconventional JavaScript runtime, being deployed against employees through email flooding and fake Microsoft Teams calls. The attack overwhelms targets and then offers a false sense [&#8230;] The post Deno-Based RAT Uses Microsoft Teams Impersonation and Mailbombing to Target Employees appeared first on C…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `2cff16eusb8mg.cloudfront.net`
- **SHA256:** `d317371cf2b4cd524849551ffd3b97d91edbc17f6b39c8693217383ba6a0370d`
- **SHA256:** `9469268c421b7821f897deb2d4d2316b21ff5da35bef417aa4e284010ef78302`
- **SHA256:** `3d8afae76c5982458849d21221e089ee161266a4248b12ea3048d1e79b76707e`
- **SHA256:** `2ed6fdfa5f9120306167ba5d8d48a62dbe5fd0d05e87c33c9784f08698f8a66b`
- **SHA256:** `3b48a334dcf0a08bed2a9766fd553474ae3014db600b65573dfee0f183e9d1d9`

## MITRE ATT&CK Techniques

- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `2cff16eusb8mg.cloudfront.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `d317371cf2b4cd524849551ffd3b97d91edbc17f6b39c8693217383ba6a0370d`, `9469268c421b7821f897deb2d4d2316b21ff5da35bef417aa4e284010ef78302`, `3d8afae76c5982458849d21221e089ee161266a4248b12ea3048d1e79b76707e`, `2ed6fdfa5f9120306167ba5d8d48a62dbe5fd0d05e87c33c9784f08698f8a66b`, `3b48a334dcf0a08bed2a9766fd553474ae3014db600b65573dfee0f183e9d1d9`


## Why this matters

Severity classified as **MED** based on: IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
