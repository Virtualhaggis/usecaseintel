<!-- curated:true -->
# [HIGH] Chinese Silk Typhoon Hacker Extradited to U.S. Over COVID Research Cyberattacks

**Source:** The Hacker News
**Published:** 2026-04-28
**Article:** https://thehackernews.com/2026/04/chinese-silk-typhoon-hacker-extradited.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

THN's reporting on the same **Silk Typhoon** extradition covered in the paired 2026-04-27 BleepingComputer briefing. Additional details from this report:

- The accused operator: **Xu Zewei**, age 34, arrested by Italian authorities in **July 2025**.
- Activity period: **February 2020 – June 2021**.
- Key victim cluster: **U.S. organisations and government agencies, including COVID-19 research entities**.

This contextualises Silk Typhoon's activity around the **2020-2021 COVID research IP-theft campaign** — Microsoft / Mandiant attributed several waves of intrusions against vaccine manufacturers, pharmaceutical research groups, and HHS-adjacent agencies to Hafnium / Silk Typhoon during that window. The same campaign also overlaps with the **ProxyLogon Exchange Server zero-day chain** (CVE-2021-26855 et al).

For SOC operations, treat this briefing as **complementary detail to the 2026-04-27 Silk Typhoon briefing** (`briefings/2026-04-27/alleged-silk-typhoon-hacker-extradited-to-us-for-cyberespion.md`) — the detection content there applies here too, with extra emphasis on the **COVID-era TTP fingerprints**:
- ProxyLogon-class web shells (still found dormant in some on-prem Exchange estates).
- Pharma/biotech research-data exfiltration patterns.
- Use of **legitimate cloud storage** (OneDrive, Box, Dropbox) for staging.

We've upgraded severity to **HIGH** for the same reasons as the paired briefing — DOJ unsealing typically accompanies fresh IOCs.

## Indicators of Compromise

- **Actor name (DOJ unsealing)**: Xu Zewei.
- **Activity dates**: Feb 2020 – Jun 2021 (use this window for retrospective hunting against pre-cloud / on-prem mailbox forensic data).
- **Victim profile**: COVID research, defense industrial base, government civilian agencies, telecoms.
- _DOJ indictment will list specific domains, email addresses, and victim sectors. Pull from the unsealed indictment when published._

## MITRE ATT&CK (analyst-validated)

Identical to the paired 2026-04-27 briefing — refer there for full table:
- **T1190** — Exploit Public-Facing Application (Exchange ProxyLogon chain)
- **T1505.003** — Web Shell (China Chopper / ASPX shells)
- **T1059.001** — PowerShell
- **T1003** — OS Credential Dumping
- **T1133** — External Remote Services
- **T1567.002** — Exfiltration to Cloud Storage

## Recommended SOC actions (priority-ordered)

1. **Use the 2026-04-27 paired briefing's detection package** — same actor, same TTPs.
2. **Expand the retrospective hunt window** to cover Feb 2020 – Jun 2021 if you retain forensic logs that far back. ProxyLogon web shells from this era are still occasionally surfaced in incident-response engagements 4 years later.
3. **Audit historical Exchange / IIS forensic data** for China-Chopper-class web shells. Cross-reference against your retained backups of `inetpub\wwwroot` / Exchange OWA paths.
4. **Pull cloud-storage exfil logs** for the same window — particularly OneDrive, Box, Dropbox APIs hit from your tenant in Q1-Q2 2021 by service accounts that no longer exist or have been replaced.
5. **Watch the DOJ docket for the Xu Zewei case** — court filings often include forensic detail (defendant work emails, infrastructure attribution, target lists) that is operationally useful.

## Splunk SPL — historic ASPX web-shell residue

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created"
      AND (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.ashx"
        OR Filesystem.file_name="*.asmx")
      AND (Filesystem.file_path="*\\inetpub\\wwwroot\\*"
        OR Filesystem.file_path="*\\Exchange\\FrontEnd\\HttpProxy\\*"
        OR Filesystem.file_path="*\\Exchange\\ClientAccess\\*"
        OR Filesystem.file_path="*\\Exchange\\OWA\\*")
      AND Filesystem._time > relative_time(now(),"-5y")
      AND NOT Filesystem.process_name IN ("msiexec.exe","TrustedInstaller.exe","msdeploy.exe","ExSetup.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path,
       Filesystem.file_name, Filesystem.user
| `drop_dm_object_name(Filesystem)`
| sort - count
```

## Defender KQL — historic file-creation residue (relies on long retention)

```kql
DeviceFileEvents
| where Timestamp > ago(180d)
| where ActionType == "FileCreated"
| where FileName endswith ".aspx" or FileName endswith ".ashx"
     or FileName endswith ".asmx"
| where FolderPath has_any ("\\inetpub\\wwwroot\\","\\Exchange\\FrontEnd\\HttpProxy\\",
                              "\\Exchange\\ClientAccess\\","\\Exchange\\OWA\\")
| where InitiatingProcessFileName !in~ ("msiexec.exe","TrustedInstaller.exe","msdeploy.exe","ExSetup.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

The Xu Zewei case is the **rare instance where a Chinese state-sponsored operator faces US prosecution** — most attributed activity ends with a Treasury sanction or sealed indictment, not extradition. Operationally:

1. The unsealed DOJ filing will publish defendant-side detail (email addresses, infrastructure, targets) that **isn't available anywhere else**. Watch for it.
2. The 2020-2021 activity window is **still operationally relevant** if your enterprise has on-prem Exchange that's been in production since then. Web shells dormant for years still surface in IR engagements.
3. **Pair this briefing with 2026-04-27** for full detection coverage. They're the same campaign at different reporting lenses.

The detection content in the paired briefing is the durable asset; this briefing's value is the COVID-research targeting context, which informs which sector / line-of-business in your enterprise is most likely to have been historically targeted.
