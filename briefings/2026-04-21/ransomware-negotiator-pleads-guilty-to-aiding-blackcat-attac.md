<!-- curated:true -->
# [HIGH] Ransomware Negotiator Pleads Guilty to Aiding BlackCat Attacks in 2023

**Source:** The Hacker News
**Published:** 2026-04-21
**Article:** https://thehackernews.com/2026/04/ransomware-negotiator-pleads-guilty-to.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

A US-based ransomware negotiator (employee at a "DigitalMint"-style firm) pleaded guilty to **aiding** BlackCat / ALPHV operators during 2023 attacks — running attacks himself or sharing access with affiliates. This is a **trust-chain story**, not a new vulnerability: the people you hire to negotiate with ransomware crews were sometimes coordinating with them.

For a SOC, the actionable takeaways aren't about today's exploit, they're about **process hygiene**:
- Negotiation firms get briefed with sensitive pre-disclosure facts (which AV detected what, which restore options exist, exact technical details of the breach).
- That brief is itself an IR artefact — if it leaks, the attacker knows exactly how to refine their next move.
- Compromised negotiators amplify the attacker's leverage on price.

## Indicators of Compromise

- _Personnel-level attribution; no technical IOCs in the article._
- The relevant control surface here is **third-party access logs and IR document handling**, not network telemetry.

## MITRE ATT&CK (analyst-validated)

- **T1199** — Trusted Relationship (the supply-chain dimension)
- **T1078.004** — Cloud Accounts (negotiators often have access via shared portals / SaaS)
- **T1556** — Modify Authentication Process (where applicable to portal access)
- **T1486** — Data Encrypted for Impact (the BlackCat payload itself)

## Recommended SOC / IR actions (priority-ordered)

1. **Audit your incident-response retainer.** What firms have access to your IR plans / runbooks / executive briefings?
2. **Compartmentalise IR data.** No single third party should have visibility into both technical IOCs and ransom-payment authorisation.
3. **Insist on dual-control on negotiation comms.** Two of your team plus the negotiator on every call. No solo phone calls.
4. **Background-check your retainers.** This wasn't a sole bad actor; it was an employee at an established firm. Ask the firm hard questions about their internal access logging and segregation of duties.
5. **Hunt for BlackCat / ALPHV indicators** if you weren't a 2023-era victim — these affiliates rebrand and reuse infra.

## Splunk SPL — known BlackCat / ALPHV process / file artefacts

```spl
| tstats `summariesonly` count min(_time) AS firstTime max(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("psexec.exe","mimikatz.exe","procdump.exe","rclone.exe")
        OR Processes.process="*--access-token=*"  -- BlackCat ALPHV CLI flag
        OR Processes.process="*--no-vmkill*"
        OR Processes.process="*--no-vm-snapshot-kill*"
        OR Processes.process="*--prop-file=*"
        OR Processes.process="*--config=*\\Public\\*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
```

## Splunk SPL — third-party access anomaly

```spl
| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.user_category="third-party"
      AND Authentication.action="success"
      AND Authentication.app IN ("vpn","jump-host","ir-portal","shared-credential-store")
    by Authentication.user, Authentication.src, Authentication.dest, _time span=1h
| `drop_dm_object_name(Authentication)`
| stats count, dc(dest) AS uniq_destinations by user
| where uniq_destinations > 5  // negotiators usually only need 1-2 specific systems
```

## Defender KQL — BlackCat ESXi-killer / rclone exfil pattern

```kql
DeviceProcessEvents
| where Timestamp > ago(180d)
| where ProcessCommandLine has_any (
    "--access-token=", "--no-vm-snapshot-kill", "--no-vmkill",
    "--prop-file=", "--no-net=", "--config=\\Users\\Public\\")
   or FileName in~ ("rclone.exe","megacmd.exe","mega-cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```

## Why this matters for your SOC

The technical hunts above are **secondary**. The primary lesson is **operational**: every IR plan needs a "what if our negotiator is compromised" branch. Document who can authorise ransom payments, what your dual-control policy is, and what data the negotiator gets vs. what stays internal. If your IR retainer has never been asked these questions, that's a finding regardless of whether you're a BlackCat target.
