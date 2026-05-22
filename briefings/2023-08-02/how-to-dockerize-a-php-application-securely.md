# [HIGH] How to Dockerize a PHP application securely

**Source:** Snyk
**Published:** 2023-08-02
**Article:** https://snyk.io/blog/dockerize-php-application/

## Threat Profile

Snyk Blog In this article
Written by James Olaogun 
August 2, 2023
0 mins read Editor's note: August 10, 2023 This post has been updated to include a more recent version of PHP in the tutorial.
Let’s say you’ve built a PHP application, but you want to separate it from supporting infrastructure in a way that keeps things lightweight, portable, and still quite secure. You’d like other developers to be able to work on it without having to recreate whole environments. In short, what you want to do w…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1543.003** — Windows Service
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Service install for persistence — sc.exe / new service registry write

`UC_SERVICE_PERSIST` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\Users\*" OR Processes.process="*\AppData\*"
        OR Processes.process="*\ProgramData\*" OR Processes.process="*\Temp\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Registry
        where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\*"
          AND Registry.registry_value_name="ImagePath"
          AND (Registry.registry_value_data="*\Users\*"
            OR Registry.registry_value_data="*\AppData\*"
            OR Registry.registry_value_data="*\Temp\*")
        by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.user
     | `drop_dm_object_name(Registry)`]
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| where ProcessCommandLine matches regex @"(?i)(\Users\|\AppData\|\ProgramData\|\Temp\)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### Article-specific behavioural hunt — How to Dockerize a PHP application securely

`UC_1382_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — How to Dockerize a PHP application securely ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/apache2/apache2.conf*" OR Filesystem.file_path="*/var/www/html*" OR Filesystem.file_path="*/etc/apache2/sites-available/*" OR Filesystem.file_path="*/var/www/*" OR Filesystem.file_path="*/etc/apache2/conf-available/*" OR Filesystem.file_path="*/home/devuser*" OR Filesystem.file_path="*/home/devuser/.composer*" OR Filesystem.file_path="*/var/www/html/vendor/bin*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — How to Dockerize a PHP application securely
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/apache2/apache2.conf", "/var/www/html", "/etc/apache2/sites-available/", "/var/www/", "/etc/apache2/conf-available/", "/home/devuser", "/home/devuser/.composer", "/var/www/html/vendor/bin"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
