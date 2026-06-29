# [MED] Using JLink to create smaller Docker images for your Spring Boot Java application

**Source:** Snyk
**Published:** 2023-08-24
**Article:** https://snyk.io/blog/jlink-create-docker-images-spring-boot-java/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
August 24, 2023
0 mins read Containers bring new flexibility and agility to software development and deployment. However, they also introduce a new attack surface that malicious actors can exploit. A compromised container can give an attacker access to other containers and even the host system. Smaller images that contain fewer artifacts are already a great help in achieving a smaller attack surface.
In this blog post, we'll present an in-depth…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Using JLink to create smaller Docker images for your Spring Boot Java applicatio

`UC_1516_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Using JLink to create smaller Docker images for your Spring Boot Java applicatio ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("javacoffeeshop.jar"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/src/project*" OR Filesystem.file_path="*/usr/src/project/target/JavaCoffeeShop.jar*" OR Filesystem.file_name IN ("javacoffeeshop.jar"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Using JLink to create smaller Docker images for your Spring Boot Java applicatio
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("javacoffeeshop.jar"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/src/project", "/usr/src/project/target/JavaCoffeeShop.jar") or FileName in~ ("javacoffeeshop.jar"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
