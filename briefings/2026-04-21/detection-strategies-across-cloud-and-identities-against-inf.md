<!-- curated:true -->
# [HIGH] Detection Strategies Across Cloud and Identities Against Infiltrating IT Workers

**Source:** Microsoft Security Blog
**Published:** 2026-04-21
**Article:** https://www.microsoft.com/en-us/security/blog/2026/04/21/detection-strategies-cloud-identities-against-infiltrating-it-workers/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Microsoft's defensive playbook on the **DPRK (North Korean) IT worker infiltration** threat — where state-sponsored operatives obtain legitimate remote IT jobs at Western companies under stolen / fabricated identities. They draw salaries (the primary funding objective), and a non-trivial percentage of them eventually pivot to **insider data theft, source code exfiltration, or extortion**.

Why this is squarely a SOC concern, not just an HR / hiring concern:
- Once hired, the operative has **valid corporate credentials**, **VPN access**, **source-tree commit rights**, **on-call rotations**, and **production access** that's earned, not stolen.
- Detection windows are months, not days — the operative is a *legitimate employee* until pivot.
- The detection signals are **identity, behavioural, and metadata** — laptop shipped to one address, signed in from a different ASN; multiple "employees" sharing a single residential IP at different employers; remote-desktop tools used at unusual hours; geographic incongruity in keyboard-layout / system-locale vs HR record.

This is the fastest-growing insider-threat class of 2025-2026 and Microsoft, CrowdStrike, Mandiant all have substantial dedicated tooling now.

## Indicators of Compromise

- _No specific IOCs — this is a behavioural/metadata threat class._
- Useful identity/network signals: residential IPs in tier-2 US cities (operative front), repeated sign-ins from VPN providers (Astrill, ExpressVPN, NordVPN), KVM-over-IP devices on corporate laptops, AnyDesk/Chrome Remote Desktop installed.

## MITRE ATT&CK (analyst-validated)

- **T1078** — Valid Accounts (the primary technique — they ARE valid)
- **T1133** — External Remote Services (VPN / VDI access)
- **T1219** — Remote Access Software (AnyDesk, Chrome Remote Desktop, TeamViewer used to share screens with handlers)
- **T1656** — Impersonation (the entire identity is fabricated)
- **T1567.002** — Exfiltration to Cloud Storage (post-pivot data theft)
- **T1213** — Data from Information Repositories: source code, design docs, customer DBs
- **T1098.001** — Account Manipulation (operative may add MFA backup methods or alt email)

## Recommended SOC actions (priority-ordered)

1. **Run remote-access-tool inventory** on all corporate laptops. AnyDesk / Chrome Remote Desktop / TeamViewer / RustDesk on a corporate device with no IT helpdesk justification is a strong signal.
2. **Cross-correlate sign-in geolocation with HR records.** If "Sarah from Austin" reliably signs in from a Russian / Chinese / Lao ASN, that's a finding.
3. **Hunt for shared residential IPs across multiple "employees"** — operative farms reuse the same physical hosts.
4. **Review device-shipping addresses** vs first-sign-in IP — operative's "laptop farm" addresses receive devices that sign in from elsewhere within 24 hours.
5. **Audit recent hires for off-hours code-repo activity, particularly bulk clones / pulls of unrelated repos.**
6. **Set up alerting for new hires who immediately push high volumes** of unrelated code to private forks.
7. **Coordinate with HR / People Ops** on identity-verification controls for fully remote roles — live-video onboarding, work-eligibility verification with document scanning.

## Splunk SPL — remote-access tool installs on corporate laptops

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
                                       "rustdesk.exe","rdesktop.exe","chrome_remote_desktop_host.exe",
                                       "remoting_host.exe","ScreenConnect.WindowsClient.exe",
                                       "Splashtop.exe","SRService.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| stats values(process_name) AS tools, count by user, dest
```

## Splunk SPL — same residential ASN signing in for multiple employees

```spl
| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
    by Authentication.src, Authentication.user
| `drop_dm_object_name(Authentication)`
| iplocation src
| stats dc(user) AS distinct_employees, values(user) AS employees by src, ASN, ASN_org
| where distinct_employees >= 2
| sort - distinct_employees
```

## Splunk SPL — geographic incongruity (sign-in vs HR record)

```spl
| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
    by Authentication.user, Authentication.src, _time span=1d
| `drop_dm_object_name(Authentication)`
| iplocation src
| lookup hr_employee_lookup user OUTPUT hr_country, hr_state
| where Country!=hr_country
| stats values(Country) AS sign_in_countries, values(hr_country) AS hr_countries,
        count by user
| where mvcount(sign_in_countries) >= 1
```

## Splunk SPL — unusual code repo bulk activity for new hires

```spl
| tstats `summariesonly` count
    from datamodel=Web
    where (Web.dest="*github.com*" OR Web.dest="*gitlab.com*"
        OR Web.dest="*bitbucket.org*" OR Web.dest="*gitea*")
      AND Web.url="*archive*"
      OR Web.url="*.zip"
    by Web.user, Web.dest, Web.url, _time span=1h
| `drop_dm_object_name(Web)`
| join type=inner user
    [| inputlookup hr_new_hires.csv
     | where hire_date_days < 60
     | fields user]
| stats sum(count) AS downloads, dc(url) AS unique_archives by user, dest
| where downloads > 5
```

## Defender KQL — remote-access tools on managed endpoints

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName in~ ("anydesk.exe","teamviewer.exe","teamviewer_service.exe",
                       "rustdesk.exe","chrome_remote_desktop_host.exe",
                       "remoting_host.exe","ScreenConnect.WindowsClient.exe",
                       "Splashtop.exe","SRService.exe")
| summarize firstSeen = min(Timestamp), lastSeen = max(Timestamp),
            executions = count(),
            users = make_set(AccountName)
            by DeviceName, FileName
| order by firstSeen asc
```

## Defender KQL — sign-in country anomaly

```kql
AADSignInEventsBeta
| where Timestamp > ago(60d)
| where ResultType == 0  // success
| summarize signins = count(),
            countries = make_set(Country),
            cities = make_set(City),
            asns = make_set(NetworkLocationDetails)
            by AccountUpn
| where array_length(countries) > 1
| extend anomalous_country = set_difference(
    countries,
    dynamic(["United States","United Kingdom","Canada","Germany","France","Australia"]))
| where array_length(anomalous_country) > 0
| order by signins desc
```

## Defender KQL — VPN-provider IP usage

```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where NetworkLocationDetails has_any ("Astrill","ExpressVPN","NordVPN","ProtonVPN",
                                          "Surfshark","M247","DataPacket","Mullvad",
                                          "BVPS","DigitalOcean","Vultr","Hetzner")
| where ResultType == 0
| summarize signins = count(), uniqueIPs = dcount(IPAddress),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp)
            by AccountUpn, NetworkLocationDetails
| order by signins desc
```

## Defender KQL — single residential IP across multiple employees

```kql
AADSignInEventsBeta
| where Timestamp > ago(60d)
| where ResultType == 0
| summarize uniqueAccounts = dcount(AccountUpn),
            accounts = make_set(AccountUpn, 50)
            by IPAddress, NetworkLocationDetails
| where uniqueAccounts >= 3
| order by uniqueAccounts desc
```

## Why this matters for your SOC

The DPRK-IT-worker threat is **the fastest-growing insider class of 2026** and the **detection burden falls largely on the SOC**, because HR processes designed for the pre-2020 in-person hiring world don't catch fabricated remote identities. The queries above are the production-deployable subset of Microsoft's broader playbook. Run the remote-access-tool query and the shared-residential-IP query first — both are fast, high-signal, and require no model tuning. If you find anything in the shared-IP query, escalate immediately to legal/HR/insider-threat — these cases need careful, evidence-preserving handling because they have legal and national-security implications beyond a normal SOC ticket.
