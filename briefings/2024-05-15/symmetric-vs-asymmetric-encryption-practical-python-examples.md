# [MED] Symmetric vs. asymmetric encryption: Practical Python examples

**Source:** Snyk
**Published:** 2024-05-15
**Article:** https://snyk.io/blog/symmetric-vs-asymmetric-encryption-python/

## Threat Profile

Snyk Blog In this article
Written by Josh Amata 
May 15, 2024
0 mins read Symmetric and asymmetric encryption are the two most common ways to protect sensitive data with cryptography. These methods use key(s) to transform an unencrypted message into an encrypted message (a ciphertext) that is extremely difficult to decrypt without the correct key(s). Symmetric encryption uses a single key to encrypt and decrypt data. In contrast, asymmetric encryption uses a pair of keys, a public and private ke…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Symmetric vs. asymmetric encryption: Practical Python examples

`UC_1323_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Symmetric vs. asymmetric encryption: Practical Python examples ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("sym_encryptor.py","asym_encryptor.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("sym_encryptor.py","asym_encryptor.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Symmetric vs. asymmetric encryption: Practical Python examples
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("sym_encryptor.py", "asym_encryptor.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("sym_encryptor.py", "asym_encryptor.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
