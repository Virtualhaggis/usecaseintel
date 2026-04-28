<!-- curated:true -->
# [HIGH] PyPI Package With 1.1M Monthly Downloads Hacked to Push Infostealer

**Source:** BleepingComputer
**Published:** 2026-04-27
**Article:** https://www.bleepingcomputer.com/news/security/pypi-package-with-11m-monthly-downloads-hacked-to-push-infostealer/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

The popular **`elementary-data`** PyPI package — **1.1 million monthly downloads** — was hijacked to ship a malicious release that **steals developer credentials and cryptocurrency wallets**. This is a high-volume PyPI package compromise — the affected blast radius is much larger than typical typosquat packages.

The pattern matches the broader **"compromised maintainer account" supply-chain class** seen across npm (the self-propagating worm earlier this month) and now PyPI:
- Attacker phishes / token-steals the maintainer's PyPI account.
- Pushes a new version with malicious code in `setup.py` / `__init__.py` / `pyproject.toml`.
- Every `pip install elementary-data` (CI, dev workstation, container build) on the affected version executes the payload.

elementary-data is a data-quality / observability tool — typically installed in **CI runners and analytics-engineer workstations**, both privileged contexts with database creds, BI service-account tokens, and cloud-warehouse keys.

We've upgraded severity to **HIGH** because:
- 1.1M monthly downloads = enormous exposure.
- The target context (data-team workstations, CI) holds prod-grade secrets.
- Infostealer payloads collect persistently — the post-exfil window stays open for months.

## Indicators of Compromise

- **Affected package**: `elementary-data` on PyPI (specific malicious version range — see Snyk / Phylum / Socket.dev advisory for exact pinning).
- _Specific malicious version + setup.py / install hook hashes should be pulled from the BleepingComputer article body or referenced security-research blog._
- Hunt focus: hosts that ran `pip install elementary-data` in the affected window; outbound from `python` to non-PyPI destinations during install events; browser credential-store reads by `python` / `pip`.

## MITRE ATT&CK (analyst-validated)

- **T1195.002** — Compromise Software Supply Chain
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1552.001** — Credentials In Files (`.aws`, `.npmrc`, `.kube`, `.env`)
- **T1567** — Exfiltration Over Web Service
- **T1657** — Financial Theft (cryptocurrency wallets)

## Recommended SOC actions (priority-ordered)

1. **Inventory `elementary-data` installations.** Hunt CI configs, container images, dev workstation `pip list` output. The fastest method is querying your container-registry image-scan reports and searching for `elementary-data` in install logs.
2. **Block the affected version range** in your private PyPI mirror / Artifactory if you have one.
3. **Hunt browser-credential-store reads by python / pip / setup.py** — see queries.
4. **Hunt cryptocurrency-wallet-path reads** by non-wallet processes.
5. **Rotate cloud / BI / warehouse credentials** for any analytics-engineer / data-platform user who installed `elementary-data` in the last 60 days.
6. **Audit your CI pipeline secret exposure.** Many data-team CI configs inject `SNOWFLAKE_*`, `BIGQUERY_*`, `DATABRICKS_*`, `AWS_*` env vars — anything captured by the infostealer.
7. **Subscribe to Phylum / Snyk / Socket.dev** PyPI compromise feeds for early warning of the next package.

## Splunk SPL — pip install of compromised package

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("pip","pip.exe","pip3","pip3.exe","python","python.exe",
                                        "python3","python3.exe","poetry","poetry.exe","uv","uv.exe")
        AND (Processes.process="*elementary-data*"
          OR Processes.process="*install*elementary*"))
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — browser credential-store reads by python/pip

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.process_name IN ("python","python.exe","python3","python3.exe",
                                        "pip","pip.exe","pip3","pip3.exe")
      AND Filesystem.action="read"
      AND (Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Login Data*"
        OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Cookies*"
        OR Filesystem.file_path="*\\Microsoft\\Edge\\User Data\\*\\Login Data*"
        OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*\\logins.json*"
        OR Filesystem.file_path="*/.config/google-chrome/Default/Login Data*"
        OR Filesystem.file_path="*/.mozilla/firefox/*"
        OR Filesystem.file_path="*Library/Application Support/Google/Chrome/*")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

## Splunk SPL — cryptocurrency-wallet path reads from non-wallet processes

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\\Exodus\\*"
        OR Filesystem.file_path="*\\Electrum\\wallets\\*"
        OR Filesystem.file_path="*\\Atomic\\*"
        OR Filesystem.file_path="*\\MetaMask\\*"
        OR Filesystem.file_path="*\\Bitcoin\\*"
        OR Filesystem.file_path="*/.electrum/*"
        OR Filesystem.file_path="*/.bitcoin/*"
        OR Filesystem.file_path="*/Library/Application Support/Exodus/*"
        OR Filesystem.file_path="*/Library/Application Support/Electrum/*")
      AND Filesystem.action="read"
      AND NOT Filesystem.process_name IN ("Exodus","Electrum","Atomic","bitcoin-qt","Bitcoin Core")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
```

## Splunk SPL — outbound from python during install events

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.process_name IN ("python.exe","python","python3","pip.exe","pip","pip3")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
      AND All_Traffic.dest!="*pypi.org*"
      AND All_Traffic.dest!="*pythonhosted.org*"
      AND All_Traffic.dest!="*github.com*"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| sort - count
```

## Defender KQL — pip install of elementary-data

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName in~ ("pip.exe","pip","pip3.exe","pip3","python.exe","python","python3.exe","python3",
                       "poetry.exe","poetry","uv.exe","uv")
| where ProcessCommandLine has "elementary-data"
   or ProcessCommandLine has "elementary_data"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — browser cred-store reads by python/pip

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe","python","python3.exe","python3",
                                         "pip.exe","pip","pip3.exe","pip3")
| where FolderPath has_any ("\\Google\\Chrome\\User Data\\",
                              "\\Microsoft\\Edge\\User Data\\",
                              "\\Mozilla\\Firefox\\Profiles\\")
   or FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```

## Defender KQL — wallet-file reads from python

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe","python","pip.exe")
| where FolderPath has_any ("\\Exodus\\","\\Electrum\\","\\Atomic\\","\\MetaMask\\",
                              "\\Bitcoin\\","/.electrum/","/.bitcoin/")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — outbound from python to non-PyPI destinations

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe","python","pip.exe","pip","python3.exe")
| where RemoteIPType == "Public"
| where RemoteUrl !has_any ("pypi.org","pythonhosted.org","github.com","githubusercontent.com",
                              "anaconda.org","conda.anaconda.org")
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

Compromised maintainer accounts on package registries are now a **monthly occurrence** — npm, PyPI, RubyGems, Cargo, OpenVSX, Docker Hub all see this pattern. The defensive posture has three layers:

1. **Detect the install** of compromised packages once advisories land (the queries above are reusable templates — just swap the package name).
2. **Detect the post-install behaviour**: browser cred-store reads, wallet reads, anomalous outbound. These are package-agnostic and catch the *next* compromise too.
3. **Reduce attack surface**: pin requirements with hashes (`--require-hashes`), use a private mirror with a delayed-promotion window (3-7 days for new releases), enforce 2FA on internal package publishers.

The third layer is the structural fix; the first two are the tactical work. Run the install-detection query for `elementary-data` against your CI logs this week — if anything matches, you have credentials to rotate.
