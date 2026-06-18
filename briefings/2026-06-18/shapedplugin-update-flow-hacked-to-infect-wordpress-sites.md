# [CRIT] ShapedPlugin update flow hacked to infect WordPress sites

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/shapedplugin-update-flow-hacked-to-infect-wordpress-sites/

## Threat Profile

ShapedPlugin update flow hacked to infect WordPress sites 
By Bill Toulas 
June 18, 2026
08:55 AM
0 


Multiple WordPress plugins from ShapedPlugin were compromised in a supply chain attack that distributed infected releases to paying customers via the vendor's official update system.


The malware delivered this way installed a fake plugin that impersonates WooCommerce components, steals credentials, and grants operators remote file-writing capabilities.


ShapedPlugin is a WordPress plug…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-10735`
- **CVE:** `CVE-2026-49777`
- **IPv4 (defanged):** `194.76.217.28`
- **Domain (defanged):** `generate.2faplugin.org`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1505.003** — Web Shell
- **T1036.005** — Match Legitimate Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ShapedPlugin malicious LicenseLoader.php file write to WP plugin directory

`UC_1_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.dest) as dest values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_name="LicenseLoader.php" OR Filesystem.file_path="*/wp-content/plugins/woocommerce-product-slider/*LicenseLoader.php" OR Filesystem.file_path="*/wp-content/plugins/easy-testimonials/*LicenseLoader.php" OR Filesystem.file_path="*/wp-content/plugins/smart-post-show/*LicenseLoader.php") by Filesystem.dest Filesystem.file_path Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "LicenseLoader.php"
    or FolderPath has_any (@"\wp-content\plugins\woocommerce-product-slider\", @"\wp-content\plugins\easy-testimonials\", @"\wp-content\plugins\smart-post-show\", @"/wp-content/plugins/woocommerce-product-slider/", @"/wp-content/plugins/easy-testimonials/", @"/wp-content/plugins/smart-post-show/") and FileName endswith ".php"
| where FileName !in~ ("index.php","readme.txt","changelog.txt")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Hidden fake WooCommerce subscription/notification plugin folder creation

`UC_1_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/wp-content/plugins/woocommerce-subscription/*" OR Filesystem.file_path="*/wp-content/plugins/woocommerce-notification/*" OR Filesystem.file_path="*\\wp-content\\plugins\\woocommerce-subscription\\*" OR Filesystem.file_path="*\\wp-content\\plugins\\woocommerce-notification\\*") by Filesystem.dest Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (@"\wp-content\plugins\woocommerce-subscription\", @"\wp-content\plugins\woocommerce-notification\", @"/wp-content/plugins/woocommerce-subscription/", @"/wp-content/plugins/woocommerce-notification/")
| where FolderPath !has "woocommerce-subscriptions"  // exclude the legit WooCommerce Subscriptions plugin (note plural)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), FileCount = dcount(FileName), Files = make_set(FileName, 25), Writers = make_set(InitiatingProcessFileName, 5) by DeviceName, FolderPath
| order by FirstSeen desc
```

### ShapedPlugin backdoor C2 callout to 2faplugin.org / 194.76.217.28

`UC_1_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.process_name) as process_name from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="194.76.217.28" OR All_Traffic.dest_ip="194.76.217.28") by All_Traffic.src All_Traffic.dest All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src from datamodel=Network_Resolution.DNS where (DNS.query="*2faplugin.org" OR DNS.answer="194.76.217.28") by DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)] | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src from datamodel=Web.Web where (Web.url="*2faplugin.org*" OR Web.dest="194.76.217.28") by Web.url Web.dest Web.http_method | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)]
```

**Defender KQL:**
```kql
union isfuzzy=true
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "194.76.217.28" or RemoteUrl has "2faplugin.org"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has "2faplugin.org" or AdditionalFields has "194.76.217.28"
| project Timestamp, DeviceName, ActionType, RemoteUrl, InitiatingProcessFileName, AdditionalFields)
| order by Timestamp desc
```

### Vulnerable ShapedPlugin Pro versions installed (CVE-2026-10735)

`UC_1_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/wp-content/plugins/woocommerce-product-slider/woocommerce-product-slider.php" OR Filesystem.file_path="*/wp-content/plugins/easy-testimonials/easy-testimonials.php" OR Filesystem.file_path="*/wp-content/plugins/smart-post-show/smart-post-show.php") by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor =~ "shapedplugin" or SoftwareName has_any ("Product Slider Pro","Real Testimonials Pro","Smart Post Show Pro")
| extend Affected = case(
    SoftwareName has "Product Slider Pro" and SoftwareVersion < "3.5.4", "yes",
    SoftwareName has "Real Testimonials Pro" and SoftwareVersion == "3.2.5", "yes",
    SoftwareName has "Smart Post Show Pro" and SoftwareVersion < "4.0.2", "yes",
    "no")
| where Affected == "yes"
| project Timestamp, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, OSPlatform
| order by DeviceName asc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
  - IP / domain IOC(s): `194.76.217.28`, `generate.2faplugin.org`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-10735`, `CVE-2026-49777`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
