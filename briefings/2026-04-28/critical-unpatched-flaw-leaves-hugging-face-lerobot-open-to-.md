<!-- curated:true -->
# [HIGH] Critical Unpatched Flaw Leaves Hugging Face LeRobot Open to Unauthenticated RCE

**Source:** The Hacker News
**Published:** 2026-04-28
**Article:** https://thehackernews.com/2026/04/critical-cve-2026-25874-leaves-hugging.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

**LeRobot** is Hugging Face's open-source robotics framework — Python-based, used in research and increasingly in production robotics deployments. **CVE-2026-25874** is critical, **unauthenticated**, and at the time of publication **unpatched**. Unauth + unpatched + RCE is the worst possible combination; treat any LeRobot deployment as actively exposed until you've isolated or removed it.

This is the third major AI/ML framework RCE in the last month (LMDeploy, SGLang, now LeRobot). The pattern is unmistakable: **adversaries are systematically targeting AI/ML infrastructure** because it's frequently Internet-facing, runs as privileged services, and isn't covered by traditional security tooling.

## Indicators of Compromise

- `CVE-2026-25874` — patch tracker (no fix at time of publication; check vendor advisory)

## MITRE ATT&CK (analyst-validated)

- **T1190** — Exploit Public-Facing Application
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1078** — Valid Accounts (none required — unauth)
- **T1083** — File and Directory Discovery (typical post-RCE recon)
- **T1071.001** — Web Protocols (post-exploit C2 over the same HTTP channel)

## Recommended SOC actions (priority-ordered)

1. **Find every LeRobot installation.** Talk to robotics / research teams. `pip list | grep lerobot` on any AI/ML host. They may be on developer laptops, lab workstations, demonstration robots — places your normal asset inventory misses.
2. **Take Internet exposure to zero.** Until patched, no LeRobot endpoint should accept inbound from outside the host. Restrict to localhost-only or behind authenticated reverse proxy.
3. **Hunt for exploitation evidence.** The hunt below catches Python-LeRobot processes spawning shells / curl / wget — the standard post-exploit pattern.
4. **Snapshot any compromised research/lab hosts** before remediation. This is unauth RCE — the host could already be a foothold into your dev/research network.

## Splunk SPL — LeRobot / Python child-process hunt

```spl
| tstats `summariesonly` count min(_time) AS firstTime max(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.parent_process_name IN ("python.exe","python3","python")
        OR Processes.process="*lerobot*")
      AND Processes.process_name IN ("cmd.exe","bash","sh","powershell.exe","curl","curl.exe",
                                       "wget","wget.exe","nc","ncat","busybox","sshd")
    by Processes.dest, Processes.user, Processes.parent_process_name,
       Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
```

## Splunk SPL — outbound from research / lab hosts

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src_category IN ("research","robotics","lab","ai-ml")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| stats sum(count) AS sessions by src, dest, dest_port
| where sessions > 5
| sort - sessions
```

## Defender KQL — LeRobot Python anomaly

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","python")
| where InitiatingProcessCommandLine has "lerobot"
| where FileName in~ ("cmd.exe","bash","sh","powershell.exe","curl","wget","nc","ncat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — vuln exposure

```kql
DeviceTvmSoftwareVulnerabilities
| where CveId =~ "CVE-2026-25874"
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```

## Why this matters for your SOC

LeRobot lives in research and lab environments — **places where security tooling coverage is typically weakest**. An unauth RCE here lands the attacker on a workstation with VPN access, SSH keys to lab infrastructure, and often privileged credentials for the broader research network. The blast radius isn't "we lost a robot demo," it's "we lost the dev/research network because nobody was watching that subnet." Triple-check that your hunt queries above can actually reach the lab subnets — that's often the gap.
