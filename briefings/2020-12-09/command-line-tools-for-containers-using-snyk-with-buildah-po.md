# [HIGH] Command line tools for containers—using Snyk with Buildah, Podman, and Skopeo

**Source:** Snyk
**Published:** 2020-12-09
**Article:** https://snyk.io/blog/command-line-tools-for-containers/

## Threat Profile

Snyk Blog In this article
Written by Matt Jarvis 
December 9, 2020
0 mins read As the container ecosystem has matured, the one thing we’re not short on is options—both in terms of the software we use, and how we plug it all together.
One of these options would be the combination of Buildah, Podman, and Skopeo—three open source command line tools with their origins in the RedHat ecosystem. As its name suggests, Buildah provides a wide range of functionality around building OCI compliant container…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Command line tools for containers—using Snyk with Buildah, Podman, and Skopeo

`UC_3252_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Command line tools for containers—using Snyk with Buildah, Podman, and Skopeo ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("single-stage.sh","host-mount.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/opt/hello*" OR Filesystem.file_path="*/usr/local/bin/hello*" OR Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_path="*/var/run/podman/podman.sock*" OR Filesystem.file_path="*/var/run/docker.sock*" OR Filesystem.file_path="*/home/matt/podman.sock*" OR Filesystem.file_path="*/etc/containers/registries.conf*" OR Filesystem.file_path="*/usr/bin/podman*" OR Filesystem.file_name IN ("single-stage.sh","host-mount.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Command line tools for containers—using Snyk with Buildah, Podman, and Skopeo
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("single-stage.sh", "host-mount.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/opt/hello", "/usr/local/bin/hello", "/usr/bin/env", "/var/run/podman/podman.sock", "/var/run/docker.sock", "/home/matt/podman.sock", "/etc/containers/registries.conf", "/usr/bin/podman") or FileName in~ ("single-stage.sh", "host-mount.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
