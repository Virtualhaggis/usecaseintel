# [HIGH] Better Ruby Gemfile security: A step-by-step guide using Snyk

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

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Better Ruby Gemfile security: A step-by-step guide using Snyk

`UC_2813_0` · phase: **install** · confidence: **High**

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


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
