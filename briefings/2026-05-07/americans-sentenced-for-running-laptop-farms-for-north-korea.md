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
Matthew Isaac Knoot and Erick Ntekereze Prince are the seventh and eighth U.S.-based "laptop farmers" sent to prison since the start of the year as part of a federal initiative targeting N…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1133** — External Remote Services
- **T1200** — Hardware Additions
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DPRK laptop-farm telltale: multiple remote-access tools installed on one corporate endpoint

`UC_32_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_name) as tools dc(Processes.process_name) as tool_count from datamodel=Endpoint.Processes where Processes.process_name IN ("anydesk.exe","AnyDesk.exe","teamviewer.exe","TeamViewer.exe","teamviewer_service.exe","TeamViewer_Service.exe","rustdesk.exe","RustDesk.exe","remoting_host.exe","chrome_remote_desktop_host.exe","SplashtopStreamer.exe","splashtopstreamer.exe","LogMeIn.exe","logmein.exe","g2mlauncher.exe","GoToMyPC.exe","gotomypc.exe","ScreenConnect.WindowsClient.exe","screenconnect.windowsclient.exe","tvnserver.exe","vncserver.exe","winvnc.exe","AteraAgent.exe","ZA.exe","Supremo.exe","NateOnMain.exe") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | stats min(firstTime) as firstTime max(lastTime) as lastTime values(process_name) as tools dc(process_name) as tool_count by dest user | where tool_count >= 2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// DPRK laptop-farm: ≥2 distinct remote-access tools observed on the same device within 14d
let _rmm_tools = dynamic([
    "anydesk.exe","teamviewer.exe","teamviewer_service.exe","rustdesk.exe",
    "chrome_remote_desktop_host.exe","remoting_host.exe",
    "splashtopstreamer.exe","sragent.exe",
    "logmein.exe","g2mlauncher.exe","gotomypc.exe",
    "screenconnect.windowsclient.exe","screenconnect.exe",
    "tvnserver.exe","vncserver.exe","winvnc.exe","ultravnc.exe",
    "ateraagent.exe","zohoassist.exe","supremo.exe","meshagent.exe",
    "nateonmain.exe","airdroid.exe","parsec.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where FileName in~ (_rmm_tools) or InitiatingProcessFileName in~ (_rmm_tools)
| extend Tool = iif(FileName in~ (_rmm_tools), tolower(FileName), tolower(InitiatingProcessFileName))
| summarize ToolCount  = dcount(Tool),
            Tools      = make_set(Tool, 20),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp),
            Users      = make_set(AccountName, 10),
            SampleCmds = make_set(ProcessCommandLine, 10)
            by DeviceId, DeviceName
| where ToolCount >= 2     // 2+ distinct RMM tools on one host = laptop-farm signature
| order by ToolCount desc, FirstSeen asc
```

### [LLM] KVM-over-IP hardware (PiKVM / TinyPilot / JetKVM) connected to corporate laptop

`UC_32_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_key_name) as keys values(Registry.registry_value_data) as vals from datamodel=Endpoint.Registry where Registry.registry_path="*\\USB\\*" (Registry.registry_value_data="*PiKVM*" OR Registry.registry_value_data="*pikvm*" OR Registry.registry_value_data="*TinyPilot*" OR Registry.registry_value_data="*tinypilot*" OR Registry.registry_value_data="*JetKVM*" OR Registry.registry_value_data="*NanoKVM*" OR Registry.registry_value_data="*CAFEBABE*") by Registry.dest Registry.user | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// KVM-over-IP hardware connected to corporate endpoint — PiKVM / TinyPilot / JetKVM / NanoKVM
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("PnpDeviceConnected","UsbDriveMounted")
| where AdditionalFields has_any ("PiKVM","pikvm","TinyPilot","tinypilot","JetKVM","jetkvm","NanoKVM","nanokvm","CAFEBABE","cafebabe")
| extend AF = parse_json(AdditionalFields)
| project Timestamp, DeviceName, DeviceId,
          ActionType,
          DeviceDescription = tostring(AF.DeviceDescription),
          ClassName         = tostring(AF.ClassName),
          VendorIds         = tostring(AF.VendorIds),
          ProductId         = tostring(AF.ProductId),
          SerialNumber      = tostring(AF.SerialNumber),
          InitiatingProcessAccountName, InitiatingProcessFileName,
          AdditionalFields
| order by Timestamp desc
```

### [LLM] Multiple distinct corporate identities authenticating from one residential / non-corporate IP

`UC_32_2` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.user) as users dc(Authentication.user) as user_count values(Authentication.app) as apps from datamodel=Authentication where Authentication.action="success" Authentication.signature_id="AADSignIn" by Authentication.src Authentication.src_category | `drop_dm_object_name(Authentication)` | where user_count >= 3 AND src_category!="corporate_egress" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// DPRK laptop-farm topology: 3+ distinct corporate UPNs sign in from one external IP within 7d
let _corp_egress = dynamic([]);  // populate with org's known VPN / proxy / NAT egress IPs
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0                                  // successful auth only
| where isnotempty(IPAddress)
| where not(ipv4_is_private(IPAddress))
| where not(ipv4_is_in_any_range(IPAddress, _corp_egress))
| where AccountUpn !contains "#EXT#"                    // exclude guests
| summarize Users      = make_set(AccountUpn, 50),
            UserCount  = dcount(AccountUpn),
            Apps       = make_set(Application, 20),
            Countries  = make_set(Country, 10),
            ASNs       = make_set(NetworkLocationDetails, 10),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp),
            SignInCount = count()
            by IPAddress
| where UserCount >= 3                                  // 3+ distinct UPNs from same public IP
| extend SpanHours = datetime_diff('hour', LastSeen, FirstSeen)
| order by UserCount desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
