<!-- curated:true -->
# [HIGH] FIRESTARTER Backdoor Hit Federal Cisco Firepower Device, Survives Security Patches

**Source:** The Hacker News
**Published:** 2026-04-24
**Article:** https://thehackernews.com/2026/04/firestarter-backdoor-hit-federal-cisco.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

CISA + UK NCSC published a joint advisory on **FIRESTARTER** — a backdoor implanted on a federal civilian agency's **Cisco Firepower (running ASA software)** appliance in **September 2025**. Two operationally important properties:

1. **Survives security patches** — the implant is designed to persist across vendor updates, meaning the standard "patch and move on" remediation doesn't evict it.
2. **Federal civilian target** — the public attribution is a strong signal of state-level capability (likely China-aligned given recent Cisco-edge campaigns: Salt Typhoon / Volt Typhoon / Velvet Ant).

Cisco Firepower / ASA is the **edge firewall on hundreds of thousands of enterprise networks** — every TLS connection, VPN session, and DC perimeter login flows through it. Implant-on-edge-device gives the attacker:
- VPN credential capture.
- TLS session metadata (with session-key extraction in some implant classes).
- A persistent foothold *outside* your internal EDR / SIEM coverage.
- Pivot point that normal network egress monitoring won't catch.

We've upgraded severity to **HIGH** because:
- Edge-device implants are the dominant 2024-2026 nation-state TTP.
- "Survives patches" means the affected enterprise community needs to **forensically validate every Firepower / ASA box**, not just patch.

## Indicators of Compromise

- **Affected family**: Cisco Firepower running Cisco ASA software.
- _Specific FIRESTARTER hashes, file paths on the device, and C2 endpoints are in the joint CISA / NCSC advisory — pull from there for ground truth._
- Hunt focus: outbound from your edge devices to non-vendor destinations; **integrity check** of system files on Firepower; new local accounts on edge devices.

## MITRE ATT&CK (analyst-validated)

- **T1542** — Pre-OS Boot (firmware-class persistence)
- **T1554** — Compromise Host Software Binary
- **T1098.004** — Account Manipulation: SSH Authorized Keys (common edge-device persistence)
- **T1556.004** — Modify Authentication Process: Network Device Authentication
- **T1601.001** — Modify System Image: Patch System Image
- **T1133** — External Remote Services
- **T1071.001** — Application Layer Protocol: Web Protocols (HTTPS C2 from device)
- **T1078** — Valid Accounts (post-compromise, the device's own credentials)

## Recommended SOC actions (priority-ordered)

1. **Run Cisco's CTID/ASA integrity verification** on every ASA / Firepower device. Cisco publishes `verify /signature` and `show software authenticity running` commands; CISA advisories typically include an updated forensic-collection script.
2. **Pull config + image off-box** for forensic comparison against known-good. If you're an enterprise with >5 Firepower units, do this *now* even without specific suspicion.
3. **Hunt outbound from your edge management addresses** — Firepower devices should talk to Cisco update servers, your AAA server, your SNMP/syslog server. Anything else is suspicious.
4. **Review new local accounts on ASA / Firepower devices** in the last 90 days.
5. **Audit AAA logs for unusual admin-tier authentications** to edge devices, particularly from non-standard source IPs.
6. **Subscribe to the Cisco PSIRT advisory feed** if you don't already — edge-device 0-days have been cadenced ~quarterly through 2024-2026.

## Splunk SPL — outbound from edge-device management IPs

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src_category IN ("firewall","edge","asa","firepower")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
      AND All_Traffic.dest!="*cisco.com*"
      AND All_Traffic.dest!="*tools.cisco.com*"
      AND All_Traffic.dest!="*talosintelligence.com*"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| sort - count
```

## Splunk SPL — new admin accounts / SSH keys on edge devices (syslog)

```spl
index=network_devices sourcetype IN ("cisco:asa","cisco:ftd","cisco:ios")
    ("user added" OR "username added" OR "ssh-key added"
     OR "configure terminal" "username "
     OR "%SEC_LOGIN-5-LOGIN_SUCCESS"
     OR "Privilege level changed")
| stats count, values(user) AS users_modified, earliest(_time) AS firstTime,
        latest(_time) AS lastTime
        by host, src
| sort - count
```

## Splunk SPL — admin auth to edge devices from unusual source

```spl
| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.dest_category IN ("firewall","edge","asa","firepower")
      AND Authentication.user_category IN ("admin","privileged","network-admin")
      AND Authentication.action="success"
    by Authentication.user, Authentication.src, Authentication.dest, _time span=1d
| `drop_dm_object_name(Authentication)`
| iplocation src
| stats values(src) AS source_ips, values(Country) AS countries,
        dc(src) AS unique_sources, count
        by user, dest
| where unique_sources > 1 OR mvcount(countries) > 1
```

## Splunk SPL — periodic outbound from edge devices (beaconing)

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src_category IN ("firewall","edge","asa","firepower")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta BETWEEN 60 AND 600
| sort - count
```

## Defender KQL — outbound from edge-device IPs (if mirrored to Defender)

```kql
let edgeDevices = dynamic(["10.0.0.1","10.0.0.2","10.0.1.1"]);  // adapt to your edge mgmt IPs
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where LocalIP in (edgeDevices) or RemoteIP in (edgeDevices)
| where RemoteIPType == "Public"
| where RemoteUrl !has_any ("cisco.com","tools.cisco.com","talosintelligence.com")
| project Timestamp, DeviceName, LocalIP, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName
| order by Timestamp desc
```

## Defender KQL — admin auth to network devices from new source

```kql
DeviceLogonEvents
| where Timestamp > ago(60d)
| where DeviceName has_any ("asa","firepower","fmc","fortigate","palo","srx")
| where ActionType == "LogonSuccess"
| where AccountName has_any ("admin","root","-da","_priv")
| summarize logons = count(),
            uniqueIPs = dcount(RemoteIP),
            ips = make_set(RemoteIP, 50)
            by AccountName, DeviceName
| where uniqueIPs > 2
| order by logons desc
```

## Why this matters for your SOC

Edge-device implants are the **single most-difficult intrusion class** to evict because:
- They're outside EDR coverage by design.
- They survive normal patch cycles (FIRESTARTER specifically).
- The vendor (Cisco / Fortinet / Palo Alto) is the only party with full forensic visibility into the device.
- Most SOCs treat the edge as a black box once it's installed.

The single most useful action is **integrity verification** — `verify /signature` on Cisco devices, cryptographic checksum verification against a known-good copy. The detection queries above catch *behaviour* (unusual outbound, new accounts), but the **authoritative answer** comes from the device itself. If your enterprise has Cisco edge gear and you've never validated image integrity, this advisory is the forcing function for that exercise. Treat *every* Firepower / ASA box as suspect until you've validated it.
