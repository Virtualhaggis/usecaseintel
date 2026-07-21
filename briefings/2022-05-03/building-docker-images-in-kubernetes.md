# [MED] Building Docker images in Kubernetes

**Source:** Snyk
**Published:** 2022-05-03
**Article:** https://snyk.io/blog/building-docker-images-kubernetes/

## Threat Profile

Snyk Blog In this article
Written by Vitalis Ogbonna 
May 3, 2022
0 mins read Hosting a CI/CD platform on Kubernetes is becoming more common among engineers. This approach saves time through automation, ensures consistent deployments, and makes it easier to monitor and manage microservices . However, building container images in Kubernetes clusters involves some technical hurdles that require workarounds.
In this article, we’ll explore some ways to build Docker images in a Kubernetes cluster for…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Building Docker images in Kubernetes

`UC_2255_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Building Docker images in Kubernetes ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/run/docker.sock*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Building Docker images in Kubernetes
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/run/docker.sock"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
