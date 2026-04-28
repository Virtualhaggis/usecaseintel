<!-- curated:true -->
# [HIGH] VECT 2.0 Ransomware Irreversibly Destroys Files Over 131KB on Windows, Linux, ESXi

**Source:** The Hacker News
**Published:** 2026-04-28
**Article:** https://thehackernews.com/2026/04/vect-20-ransomware-irreversibly.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

VECT 2.0 is **destructive malware masquerading as ransomware**. Rather than encrypt files (which can be reversed by paying), it **truncates / overwrites everything over 131KB**, leaving smaller files intact to keep the system bootable. Cross-platform: Windows, Linux, **and ESXi** — the latter is the alarming part. ESXi targeting matches the LockBit/Akira/Royal/Conti playbook of crippling virtualised infrastructure to maximise impact.

The 131KB threshold is a deliberate speed-vs-impact trade-off: skipping small files keeps the OS bootable while destroying business data — meaning a paying victim still cannot recover. Treat as **wiper, not ransomware** for incident response purposes (no decryption key exists; backups are the only recovery path).

## Indicators of Compromise

- _No public IOCs in the RSS summary at time of writing._
- Watch the article body and follow-up reporting (HHS HC3, Microsoft Threat Intelligence, Mandiant) for hashes and ESXi-targeting infrastructure.

## MITRE ATT&CK (analyst-validated)

- **T1486** — Data Encrypted for Impact (the masquerading category)
- **T1485** — Data Destruction (the actual behaviour — files overwritten irreversibly)
- **T1490** — Inhibit System Recovery (likely deletes shadow copies / vSphere snapshots)
- **T1021.002** — SMB/Windows Admin Shares (lateral spread before mass-destruction)
- **T1003.001** — LSASS Memory (typical pre-destruction credential theft for lateral movement)
- **T1561.001** — Disk Content Wipe (ESXi-specific — directly hitting `.vmdk` files)

## Recommended SOC actions (priority-ordered)

1. **Verify ESXi exposure.** Inventory every ESXi host. Confirm SSH disabled, Web GUI not Internet-facing, vCenter credentials rotated within last 90 days.
2. **Backup integrity check.** Confirm immutable / air-gapped backups exist for VM data. With a wiper there is no decryption — backups are the *only* recovery path.
3. **Hunt for pre-cursor activity.** The destructive payload runs late; the lateral movement and credential theft happen first. Run the SPL/KQL below.
4. **Block known ransomware tools.** AnyDesk / TeamViewer / RustDesk if they're not approved for IT use — destructive actors love these for hands-on-keyboard access.

## Splunk SPL — mass-file-modification anomaly (wiper signal)

```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed","deleted")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

## Splunk SPL — ESXi-host SSH session correlation

```spl
| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.dest_category="esxi"
      AND Authentication.app="ssh"
      AND Authentication.action="success"
    by Authentication.user, Authentication.src, Authentication.dest, _time span=1h
| `drop_dm_object_name(Authentication)`
| stats count, dc(dest) AS distinct_esxi_hosts by user, src
| where distinct_esxi_hosts > 3
```

## Defender KQL — mass-modification on Windows endpoints

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed","FileModified","FileDeleted")
| summarize files = dcount(FileName), bytes_touched = sum(FileSize)
    by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
| order by files desc
```

## Defender KQL — LSASS access pre-destruction (typical kill chain step)

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe","svchost.exe",
                                          "wininit.exe","services.exe","lsm.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

## Why this matters for your SOC

A destructive wiper masquerading as ransomware shifts your incident response posture entirely. Negotiation is **off the table** — paying does nothing. The window between detection of pre-cursor activity (credential theft, lateral movement, ESXi enumeration) and the destructive payload is your only opportunity to contain. ESXi presence in the article means this isn't a workstation-only event; the worst-case is virtualised production infrastructure being wiped wholesale. **Backups + immutable storage + ESXi hardening are the only proven defences.** Don't bet on detection of the actual wiper — by then it's too late.
