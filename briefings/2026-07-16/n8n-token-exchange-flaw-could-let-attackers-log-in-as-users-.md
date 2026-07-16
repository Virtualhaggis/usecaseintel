# [CRIT] n8n Token Exchange Flaw Could Let Attackers Log In as Users From Another Issuer

**Source:** The Hacker News
**Published:** 2026-07-16
**Article:** https://thehackernews.com/2026/07/n8n-token-exchange-flaw-could-let.html

## Threat Profile

n8n Token Exchange Flaw Could Let Attackers Log In as Users From Another Issuer 
 Swati Khandelwal  Jul 16, 2026 Vulnerability / Web Security 
n8n , the workflow automation platform, handed out the wrong accounts at login. On Enterprise instances configured to trust more than one external token issuer, it matched an incoming JWT to a local user on the sub claim alone and ignored iss .
A valid token from issuer A carrying a sub that belongs to someone under issuer B logged you in as them. Their…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-59208`
- **CVE:** `CVE-2026-54305`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1556** — Modify Authentication Process

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable n8n version exposed to CVE-2026-59208 cross-issuer token-exchange auth bypass

`UC_4_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-59208" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where Timestamp > ago(1d)
| where SoftwareName has "n8n"
| where (parse_version(SoftwareVersion) < parse_version("2.27.4")) or (SoftwareVersion == "2.28.0")
| project Timestamp, DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus
| order by DeviceName asc
```

### n8n token-exchange feature enabled — CVE-2026-59208 exploitation precondition (N8N_TOKEN_EXCHANGE_TRUSTED_KEYS)

`UC_4_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*N8N_TOKEN_EXCHANGE_TRUSTED_KEYS*" by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "N8N_TOKEN_EXCHANGE_TRUSTED_KEYS" or InitiatingProcessCommandLine has "N8N_TOKEN_EXCHANGE_TRUSTED_KEYS"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), SampleCmd=any(ProcessCommandLine) by DeviceName, AccountName, FileName
| order by LastSeen desc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-59208`, `CVE-2026-54305`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
