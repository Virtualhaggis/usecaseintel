# [HIGH] Recruitment red flags: Can you spot a spy posing as a job seeker?

**Source:** ESET WeLiveSecurity
**Published:** 2025-10-28
**Article:** https://www.welivesecurity.com/en/business-security/recruitment-spot-spy-job-seeker/

## Threat Profile

Back in July 2024, cybersecurity vendor KnowBe4 began to observe suspicious activity linked to a new hire. The individual began manipulating and transferring potentially harmful files, and tried to execute unauthorized software. He was subsequently found out to be a North Korean worker who had tricked the firm’s HR team into gaining remote employment with the firm. In all, the individual managed to pass four video conference interviews as well as a background and pre-hiring check.
The incident u…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1078** — Valid Accounts
- **T1133** — External Remote Services
- **T1090.003** — Multi-hop Proxy
- **T1090.002** — External Proxy
- **T1078.004** — Cloud Accounts
- **T1200** — Hardware Additions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] RMM tooling executed on a newly-onboarded employee's first-issue laptop (WageMole/Jasper Sleet)

`UC_300_0` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process from datamodel=Endpoint.Processes where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe","RustDesk.exe","AnyViewer.exe","JumpConnect.exe","JumpDesktopConnect.exe","ScreenConnect.ClientService.exe","ChromeRemoteDesktopHost.exe","remoting_host.exe","AteraAgent.exe","tinypilot.exe") by Processes.user Processes.dest Processes.process_name Processes.process_path
| `drop_dm_object_name(Processes)`
| lookup hr_new_hires_lookup user OUTPUT hire_date employment_country shipping_country
| eval hire_age_days = round((now() - strptime(hire_date,"%Y-%m-%d")) / 86400, 0)
| where hire_age_days <= 30 AND isnotnull(hire_date)
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let RMMTools = dynamic(["anydesk.exe","teamviewer.exe","teamviewer_service.exe","rustdesk.exe","anyviewer.exe","jumpconnect.exe","jumpdesktopconnect.exe","screenconnect.clientservice.exe","chromeremotedesktophost.exe","remoting_host.exe","ateraagent.exe","tinypilot.exe"]);
let NewHires = IdentityInfo
| where CreatedDateTime > ago(30d)
| summarize HireDate=min(CreatedDateTime) by AccountUpn=tolower(AccountUpn);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (RMMTools) or InitiatingProcessFileName in~ (RMMTools)
| extend AccountUpn = tolower(AccountUpn)
| join kind=inner NewHires on AccountUpn
| where Timestamp between (HireDate .. HireDate + 30d)
| project Timestamp, DeviceName, AccountUpn, HireDate, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256
```

### [LLM] New-hire Entra ID sign-in from commercial VPN / residential-proxy / VPS ASN with country mismatch

`UC_300_1` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src_ip values(Authentication.src_country) as src_country values(Authentication.app) as app from datamodel=Authentication where Authentication.signature_id IN ("4624","AAD_SignIn") AND Authentication.action="success" by Authentication.user Authentication.user_agent
| `drop_dm_object_name(Authentication)`
| lookup hr_new_hires_lookup user OUTPUT hire_date shipping_country
| eval hire_age_days = round((now() - strptime(hire_date,"%Y-%m-%d")) / 86400, 0)
| where hire_age_days <= 60
| iplocation src_ip
| lookup vpn_proxy_vps_asn_lookup ASN OUTPUT asn_category
| where asn_category IN ("commercial_vpn","residential_proxy","vps_hoster","tor_exit") OR (isnotnull(shipping_country) AND Country!=shipping_country)
| stats count dc(src_ip) as ip_count values(src_ip) as src_ips values(Country) as countries values(asn_category) as asn_cats by user shipping_country hire_date
```

**Defender KQL:**
```kql
let NewHires = IdentityInfo | where CreatedDateTime > ago(60d) | project AccountUpn=tolower(AccountUpn), HireDate=CreatedDateTime, ShippingCountry=Country;
let AnonInfraIndicators = dynamic(["vpn","proxy","hosting","tor","anonymizer","datacenter"]);
AADSignInEventsBeta
| where Timestamp > ago(60d)
| where ErrorCode == 0
| extend AccountUpn = tolower(AccountUpn)
| join kind=inner NewHires on AccountUpn
| where Timestamp between (HireDate .. HireDate + 60d)
| extend NetSig = tostring(parse_json(NetworkLocationDetails))
| where NetSig has_any (AnonInfraIndicators) or (isnotempty(ShippingCountry) and Country != ShippingCountry) or IsAnonymousProxy == true
| project Timestamp, AccountUpn, IPAddress, Country, City, ShippingCountry, NetSig, ISP, UserAgent, RiskState, RiskLevelDuringSignIn, ConditionalAccessStatus
```

### [LLM] PiKVM / TinyPilot IP-KVM device attached to a corporate endpoint (laptop-farm indicator)

`UC_300_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query values(DNS.answer) as answer from datamodel=Network_Resolution where DNS.query IN ("*.pikvm.org","api.pikvm.org","updates.pikvm.org","*.tinypilotkvm.com","updates.tinypilotkvm.com","licensing.tinypilotkvm.com") by DNS.src DNS.dest
| `drop_dm_object_name(DNS)`
| append [
  | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.process_name IN ("ustreamer.exe","kvmd.exe","tinypilot.exe") OR Processes.process="*pikvm*" OR Processes.process="*tinypilot*" by Processes.user Processes.dest Processes.process_name
  | `drop_dm_object_name(Processes)` ]
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let KvmHwStrings = dynamic(["pikvm","tinypilot","kvmd","ustreamer","raspberry pi compute module","linux foundation multifunction"]);
let KvmDomains = dynamic(["pikvm.org","api.pikvm.org","updates.pikvm.org","tinypilotkvm.com","licensing.tinypilotkvm.com"]);
union isfuzzy=true
  (DevicePnpEvents
    | where Timestamp > ago(30d)
    | extend lower_extra = tolower(strcat(tostring(AdditionalFields), " ", tostring(ClassName), " ", tostring(VendorIds), " ", tostring(DeviceIds)))
    | where lower_extra has_any (KvmHwStrings) or VendorIds has "VID_1D6B" and DeviceIds has "PID_0104"
    | project Timestamp, DeviceName, ActionType, ClassName, VendorIds, DeviceIds, AdditionalFields),
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (KvmDomains)
    | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort)
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
