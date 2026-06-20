# [HIGH] Supply chain security incident at CircleCI: Rotate your secrets

**Source:** Snyk
**Published:** 2023-01-07
**Article:** https://snyk.io/blog/supply-chain-security-incident-circleci-secrets/

## Threat Profile

Snyk Blog In this article
Written by Sonya Moisset 
Vandana Verma Sehgal 
January 7, 2023
0 mins read On January 4, CircleCI, an automated CI/CD pipeline setup tool, reported a security incident in their product by sharing an advisory .
Context around the CircleCI Incident On December 27, security engineer Daniel HÃ¼ckmann received an email notification about a potential intrusion in his CircleCI account thanks to an AWS CanaryToken placed by him. The decoy, in the form of an AWS key, was likely…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `178.249.214.10`
- **IPv4 (defanged):** `89.36.78.75`
- **IPv4 (defanged):** `89.36.78.109`
- **IPv4 (defanged):** `89.36.78.135`
- **IPv4 (defanged):** `178.249.214.25`
- **IPv4 (defanged):** `72.18.132.58`
- **IPv4 (defanged):** `188.68.229.52`
- **IPv4 (defanged):** `111.90.149.55`
- **Domain (defanged):** `potrax.com`
- **SHA256:** `8913e38592228adc067d82f66c150d87004ec946e579d4a00c53b61444ff35bf`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `178.249.214.10`, `89.36.78.75`, `89.36.78.109`, `89.36.78.135`, `178.249.214.25`, `72.18.132.58`, `188.68.229.52`, `111.90.149.55` _(+1 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8913e38592228adc067d82f66c150d87004ec946e579d4a00c53b61444ff35bf`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
