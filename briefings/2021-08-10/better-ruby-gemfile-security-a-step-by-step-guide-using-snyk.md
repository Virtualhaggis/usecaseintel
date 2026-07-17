# [CRIT] Better Ruby Gemfile security: A step-by-step guide using Snyk

**Source:** Snyk
**Published:** 2021-08-10
**Article:** https://snyk.io/blog/better-ruby-gemfile-security-step-by-step-guide-snyk/

## Threat Profile

Snyk Blog In this article
Written by DeveloperSteve Coochin 
August 10, 2021
0 mins read Ruby is a well-defined and thought-out language and has been around since the mid-1990s. In 2004, Ruby incorporated RubyGems as its package manager. RubyGems is used to manage libraries and dependencies in a self-contained format known as a gem. The interface for RubyGems is a command line tool that integrates with the Ruby runtime and allows Gemfiles to be added or updated in a project.
I looked at three Ru…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-8184`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Better Ruby Gemfile security: A step-by-step guide using Snyk

`UC_3088_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Better Ruby Gemfile security: A step-by-step guide using Snyk ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/local/opt/openssl/lib/*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Better Ruby Gemfile security: A step-by-step guide using Snyk
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/local/opt/openssl/lib/"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-8184`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
