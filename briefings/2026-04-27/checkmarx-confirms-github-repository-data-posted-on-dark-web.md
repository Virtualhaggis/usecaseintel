<!-- curated:true -->
# [HIGH] Checkmarx Confirms GitHub Repository Data Posted on Dark Web After March 23 Attack

**Source:** The Hacker News
**Published:** 2026-04-27
**Article:** https://thehackernews.com/2026/04/checkmarx-confirms-github-repository.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Checkmarx confirmed that **data from its GitHub repository has been published on the dark web** by the actors behind the **March 23, 2026 supply-chain incident** (the same campaign that produced the Bitwarden CLI compromise and malicious KICS Docker images briefings earlier in this batch).

This is the **third disclosure stage** of the incident:
1. **Initial compromise** (March 23) — supply-chain breach giving access to Checkmarx's internal systems.
2. **Downstream package compromise** (April 22-23) — malicious KICS Docker images, trojanised Bitwarden CLI npm package.
3. **Repository data leak** (April 27) — internal source code / config / secrets dumped.

For SOC operations, the **GitHub-repo-leak stage** is the one that creates persistent risk for any Checkmarx customer:
- Internal code may include Checkmarx's own customer-facing detection logic — adversaries can study it for evasion.
- Repository config files often contain customer integration details (API endpoints, sample tenant IDs, default credentials).
- Any *secrets* committed to the repo (even if rotated) are now public dark-web information.

We've upgraded severity to **HIGH** because the affected community is **every Checkmarx customer** that uses KICS, Checkmarx One, or any Checkmarx-integrated CI tooling.

## Indicators of Compromise

- _Dark-web-published file lists / sample posts will be in security-research write-ups (Hudson Rock, KELA, IntelX). Pull from there if your tenant is affected._
- Checkmarx will publish customer-impact-specific advisory; subscribe and read it.

## MITRE ATT&CK (analyst-validated)

- **T1195.002** — Compromise Software Supply Chain
- **T1199** — Trusted Relationship
- **T1213.003** — Code Repositories
- **T1552.001** — Credentials In Files
- **T1567.002** — Exfiltration to Cloud Storage
- **T1078** — Valid Accounts (downstream — what attackers do with leaked secrets)

## Recommended SOC actions (priority-ordered)

1. **Inventory your Checkmarx exposure.** Are you a Checkmarx One / KICS customer? Which engineering teams use it? Which CI pipelines integrate it? What credentials / API tokens does the integration hold?
2. **Rotate every Checkmarx-integration secret.** Even if not directly named in the leak, assume exposure: Checkmarx API tokens, GitHub PATs used for the integration, container registry creds.
3. **Review the dark-web-leaked file list** for any direct mention of your organisation. Hudson Rock / KELA / Recorded Future intel feeds will have indexed the dump.
4. **Audit Checkmarx-related infrastructure** — webhook URLs, CI configs, container registry mirrors. Anything that depended on Checkmarx-published manifests should be re-validated.
5. **Re-evaluate trust relationships** in your supply-chain tooling. The Checkmarx incident is a worked example of why a single-vendor supply-chain security stack is itself a single point of failure.

## Splunk SPL — Checkmarx CI integration calls

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where (All_Traffic.dest="*checkmarx.com*"
        OR All_Traffic.dest="*checkmarx.net*"
        OR All_Traffic.dest="*checkmarx-cdn*"
        OR All_Traffic.dest="*ast.checkmarx.net*"
        OR All_Traffic.dest="*sca.checkmarx.com*"
        OR All_Traffic.process_name="*kics*"
        OR All_Traffic.process_name="*cx-ast*")
      AND All_Traffic.action="allowed"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port,
       All_Traffic.user, All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| sort - count
```

## Splunk SPL — KICS / cx-ast process activity (covers earlier docker briefing)

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("kics","kics.exe","cx-ast","cx-ast.exe","cxsast")
        OR Processes.process="*checkmarx/kics*"
        OR Processes.process="*kics:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — GitHub PAT or token reuse anomaly

```spl
index=github sourcetype=github:audit
    action IN ("oauth_authorization.update","personal_access_token.access_revoked",
                "personal_access_token.create","integration_installation.repositories_added")
| stats values(actor_ip) AS source_ips, dc(actor_ip) AS unique_ips,
        earliest(_time) AS firstTime, latest(_time) AS lastTime
        by actor, action
| where unique_ips > 2
| sort - lastTime
```

## Defender KQL — Checkmarx integration outbound

```kql
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteUrl has_any ("checkmarx.com","checkmarx.net","ast.checkmarx.net",
                            "sca.checkmarx.com","checkmarx-cdn")
   or InitiatingProcessFileName has_any ("kics","cx-ast","cxsast")
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — KICS / Checkmarx tool execution

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName in~ ("kics","kics.exe","cx-ast","cx-ast.exe","cxsast","cxsast.exe")
   or ProcessCommandLine has_any ("checkmarx/kics","kics:v","cx-ast","cxsast")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

The Checkmarx incident demonstrates the **cascading-disclosure pattern** — one vendor compromise generates 3+ disclosures over weeks as the actors monetise and the vendor catches up. Each disclosure stage requires fresh defender action:

1. *Initial compromise* → assess supplier exposure.
2. *Downstream package compromise* → block / patch affected packages.
3. *Repository data leak* → rotate credentials, audit usage, treat repo data as adversary intel.

Cross-reference the related briefings in this archive: `briefings/2026-04-23/bitwarden-cli-compromised-in-ongoing-checkmarx-supply-chain-.md` and `briefings/2026-04-22/malicious-kics-docker-images-and-vs-code-extensions-hit-chec.md`. Treat the Checkmarx campaign as **one incident with three disclosures**, not three separate incidents.

The structural lesson for your supply-chain security strategy is **don't single-vendor**. If your detection-as-code, IaC scanner, SBOM tool, and runtime CWPP all come from one vendor, that vendor becomes the highest-value supply-chain target in your stack.
