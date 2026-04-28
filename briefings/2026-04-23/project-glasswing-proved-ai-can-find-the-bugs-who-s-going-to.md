<!-- curated:true -->
# [HIGH] Project Glasswing Proved AI Can Find the Bugs — Who's Going to Fix Them?

**Source:** The Hacker News
**Published:** 2026-04-23
**Article:** https://thehackernews.com/2026/04/project-glasswing-proved-ai-can-find.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

A trend / strategy article surfaced by Anthropic's announcement of **Project Glasswing** — an AI model effective enough at finding software vulnerabilities that Anthropic **postponed its public release** and granted private access to Apple / Microsoft / Google / Amazon / a coalition of major vendors. The premise:
- AI-driven vulnerability discovery is now **operationally effective at scale** (the **Mythos Preview** that led to Glasswing reportedly found a substantial volume of real bugs).
- The same capability is **available to (or can be replicated by) adversaries**.
- Defender-side patching cycles are **slower than the discovery rate** — leading to a "zero-window" or "negative-window" reality where vulns are exploited before patches ship.

For SOCs, this is a **shift in defender posture** rather than a single-CVE issue:
- The traditional model (vendor patches → customer deploys → window closes) is breaking. Patch-when-possible is no longer enough.
- Compensating controls and **detection-first** posture become increasingly critical.
- The **mean time from disclosure to in-the-wild exploit** has been falling for years; AI-assisted discovery accelerates that.

We've upgraded severity to **HIGH** as a strategic / posture item — not because there's a specific TTP today, but because the **underlying assumption shift** affects every patch / detect / contain decision the SOC will make for the next 18 months.

## Indicators of Compromise

- _No IOCs — strategy / industry-shift article._
- The actionable read is your **mean time to deploy critical patches** and your **detection coverage of the unknowable-future-CVE class**.

## MITRE ATT&CK (analyst-validated)

- **T1190** — Exploit Public-Facing Application (the broader threat class enabled by faster discovery)
- **T1589.001** — Gather Victim Identity Information (recon often precedes exploitation regardless of how the vuln was found)

## Recommended SOC actions (priority-ordered)

1. **Audit your "patch the day a CVE drops" capability.** Most enterprises have 30-90 day average patch cadence even for criticals. The new exploitation reality requires faster — ideally <7 days for internet-facing, <1 day for actively-exploited.
2. **Build detection content that targets *technique classes*, not specific CVEs.** When the CVE-to-exploit window collapses, the only sustainable defence is generic technique detection (web shell drops, suspicious child processes from server-side processes, anomalous outbound from edge devices).
3. **Internet attack surface management as a continuous program**, not a quarterly scan. External attack-surface tools (Censys, Shodan, Microsoft Defender External ASM) should feed your asset inventory continuously.
4. **Compensating controls for unpatchable systems**: WAF rules, segmentation, IPS signatures, micro-segmentation. Many organisations have unpatchable systems; those need defence-in-depth more than ever.
5. **Tabletop the "zero-day disclosed at 2pm Friday" scenario**: who's authorised to take systems offline, how fast can you push a WAF rule, what's the comms plan?
6. **Subscribe to Anthropic / Microsoft / Google joint-disclosure feeds** if/when they emerge — Project Glasswing's coalition is the obvious public-private intelligence-sharing organism for the next year.

## Splunk SPL — internet-facing asset exposure inventory

```spl
| tstats `summariesonly` count
    from datamodel=Vulnerabilities
    where Vulnerabilities.severity IN ("critical","high")
      AND Vulnerabilities.dest_category IN ("internet","external","dmz")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.cve,
       Vulnerabilities.severity
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

## Splunk SPL — generic web-shell detection (technique-class)

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created"
      AND (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.ashx"
        OR Filesystem.file_name="*.asmx" OR Filesystem.file_name="*.cshtml"
        OR Filesystem.file_name="*.php" OR Filesystem.file_name="*.jsp"
        OR Filesystem.file_name="*.jspx")
      AND (Filesystem.file_path="*\\inetpub\\*"
        OR Filesystem.file_path="*\\wwwroot\\*"
        OR Filesystem.file_path="*\\webapps\\*"
        OR Filesystem.file_path="*/var/www/*"
        OR Filesystem.file_path="*/usr/share/nginx/*")
      AND NOT Filesystem.process_name IN ("msiexec.exe","TrustedInstaller.exe","msdeploy.exe",
                                            "github-runner.exe","jenkins.exe","docker.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path,
       Filesystem.file_name, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

## Splunk SPL — generic edge-device anomalous outbound (technique-class)

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src_category IN ("firewall","edge","loadbalancer","vpn-gateway","waf")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
      AND All_Traffic.dest!="*update.cisco.com*"
      AND All_Traffic.dest!="*update.fortinet.com*"
      AND All_Traffic.dest!="*update.paloaltonetworks.com*"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| sort - count
```

## Defender KQL — vuln exposure pivot

```kql
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ("Critical","High")
| join kind=inner (DeviceInfo
    | where IsInternetFacing == true) on DeviceId
| join kind=inner DeviceTvmSoftwareVulnerabilitiesKB on CveId
| where IsExploitAvailable == true
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel,
          RecommendedSecurityUpdate, PublishedDate
| order by PublishedDate desc
```

## Defender KQL — server-side process spawning shells (broad coverage)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("w3wp.exe","tomcat.exe","java.exe","node.exe",
                                         "httpd.exe","nginx.exe","python.exe",
                                         "dotnet.exe","Kestrel.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","zsh",
                       "wmic.exe","whoami.exe","systeminfo.exe","tasklist.exe","net.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

The Glasswing announcement marks a **discontinuity in the attacker / defender economics** — not because Anthropic's model itself reaches adversaries, but because the underlying capability (LLM-assisted vulnerability discovery) is widely-replicated and only getting better. The strategic implications:

1. **Shorten patch windows aggressively**, especially for internet-facing assets.
2. **Invest in technique-class detection** — generic web-shell, generic suspicious-server-child-process, generic anomalous-outbound — because the *specific* CVE you'll be hit by hasn't been disclosed yet.
3. **Continuous attack-surface visibility** is becoming non-optional.
4. **Compensating controls** (WAF, IPS, segmentation) carry more weight when patching can't keep up.

The detections above are the bedrock of technique-class coverage. They don't get less valuable as new CVEs land; they catch the *exploitation behaviour*, regardless of which specific vuln got chained. Build that detection backbone now — Glasswing is one announcement; the underlying trend won't reverse.
