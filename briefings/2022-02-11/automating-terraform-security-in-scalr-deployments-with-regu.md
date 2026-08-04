# [MED] Automating Terraform security in Scalr deployments with Regula [Tutorial]

**Source:** Snyk
**Published:** 2022-02-11
**Article:** https://snyk.io/blog/automating-terraform-security-in-scalr-deployments-with-regula-tutorial/

## Threat Profile

Snyk Blog In this article
Written by Aidan O’Connor 
February 11, 2022
0 mins read Editor's note This blog originally appeared on fugue.co. Fugue joined Snyk in 2022 and is a key component of Snyk IaC .
Introduction to Regula and Scalr Integration Regula Regula  enables cloud teams to evaluate Terraform, CloudFormation, Azure Resource Manager, and Kubernetes Infrastructure-as-Code (IaC) for security and compliance violations prior to deployment. Regula is an open source implementation of  Rego ,…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Automating Terraform security in Scalr deployments with Regula [Tutorial]

`UC_2636_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Automating Terraform security in Scalr deployments with Regula [Tutorial] ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/local/bin*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Automating Terraform security in Scalr deployments with Regula [Tutorial]
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/local/bin"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
