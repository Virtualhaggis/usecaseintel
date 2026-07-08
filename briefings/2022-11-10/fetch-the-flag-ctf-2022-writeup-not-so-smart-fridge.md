# [HIGH] Fetch the Flag CTF 2022 writeup: Not So Smart Fridge

**Source:** Snyk
**Published:** 2022-11-10
**Article:** https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-not-so-smart-fridge/

## Threat Profile

Snyk Blog In this article
Written by Antonio Gomes 
November 10, 2022
0 mins read Thanks for playing Fetch with us! Congrats to the thousands of players who joined us for Fetch the Flag CTF . And a huge thanks to the Snykers that built, tested, and wrote up the challenges! 
This Fetch the Flag CTF challenge starts with a warm welcome, giving us all the necessary information about our shiny new Smart Fridge Ultra SFU-3000 ! Exciting, right?
Isaac Asimov once predicted, “Whole, semi-prepared meals…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-26068`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Pistache CVE-2022-26068 path traversal reading /etc/passwd via /doc/../

`UC_1895_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/doc/*" AND Web.url="*../*") AND (Web.url="*etc/passwd*" OR Web.url="*etc/shadow*") AND Web.status IN ("200","206") by Web.src Web.dest Web.url Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### Pistache binary theft via /doc/../../proc/self/exe path traversal

`UC_1895_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*proc/self/exe*" AND Web.status IN ("200","206") by Web.src Web.dest Web.url Web.http_user_agent Web.bytes_out Web.status
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### curl --path-as-is traversal command exfiltrating /proc/self/exe or /etc/passwd

`UC_1895_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="curl" OR Processes.process_name="curl.exe") AND Processes.process="*--path-as-is*" AND (Processes.process="*/../*" OR Processes.process="*proc/self/exe*" OR Processes.process="*etc/passwd*" OR Processes.process="*etc/shadow*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "curl" or FileName =~ "curl.exe"
| where ProcessCommandLine has "--path-as-is"
| where ProcessCommandLine has_any ("/../","proc/self/exe","etc/passwd","etc/shadow")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-26068`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
