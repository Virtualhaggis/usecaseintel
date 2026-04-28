# Shared Detection Templates

Generic IOC-substitution hunts referenced from per-article briefings. Each
briefing lists the IOC values that fired (CVEs, defanged IPs / domains,
file hashes); the queries below are the canonical SPL / KQL bodies you'd
substitute those values into.

---

<a id="asset-exposure"></a>
## Asset Exposure — Vulnerability Matches Article CVE(s)

**Phase:** recon · **Confidence:** High · **Technique:** T1190 — Exploit Public-Facing Application

**When to use:** an article names one or more CVEs and you want to know
whether your estate has unpatched assets that match.

### Splunk SPL (CIM `Vulnerabilities`)

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Vulnerabilities
    where Vulnerabilities.signature IN (<CVE_LIST>)
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

### Defender KQL (`DeviceTvmSoftwareVulnerabilities`)

```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ (<CVE_LIST>)
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by VulnerabilitySeverityLevel desc
```

---

<a id="network-ioc"></a>
## Network Connections to Article IPs / Domains

**Phase:** c2 · **Confidence:** High · **Technique:** T1071 — Application Layer Protocol

**When to use:** an article publishes defanged IPs or domains as
attacker C2 / staging infrastructure.

### Splunk SPL (CIM `Network_Traffic` / `Web` / `Network_Resolution`)

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest IN (<IP_LIST>)
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| append
    [| tstats `summariesonly` count from datamodel=Web
        where Web.dest IN (<DOMAIN_LIST>)
        by Web.src, Web.dest, Web.url, Web.user
     | `drop_dm_object_name(Web)`]
| append
    [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
        where DNS.query IN (<DOMAIN_LIST>)
        by DNS.src, DNS.query, DNS.answer
     | `drop_dm_object_name(DNS)`]
```

### Defender KQL (`DeviceNetworkEvents`)

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in (<IP_LIST>) or RemoteUrl has_any (<DOMAIN_LIST>)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

<a id="hash-ioc"></a>
## File Hash IOCs — Endpoint File / Process Match

**Phase:** install · **Confidence:** High · **Technique:** T1027 — Obfuscated Files or Information

**When to use:** an article publishes SHA256 / SHA1 / MD5 hashes for
malicious binaries.

### Splunk SPL (CIM `Endpoint.Filesystem` + `Endpoint.Processes`)

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN (<HASH_LIST>)
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.process_hash IN (<HASH_LIST>)
        by Processes.dest, Processes.user, Processes.process_name, Processes.process_hash]
```

### Defender KQL (`DeviceFileEvents` + `DeviceProcessEvents`)

```kql
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ (<HASH_LIST>) or SHA1 in~ (<HASH_LIST>) or MD5 in~ (<HASH_LIST>)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

## Why these are split out

These three hunts fire on **most** briefings — every article that names
a CVE, an IP/domain, or a hash triggers one of them. The SPL / KQL bodies
don't change between articles; only the IOC list does.

Inlining the same boilerplate on every briefing was redundant noise that
made it harder to spot the *article-specific* detection content. Now
each briefing renders the IOC list inline (so you can copy-paste the
values straight into your search) and links here for the body once.

For machine consumption, the same IOC list is also exported to:

- `intel/iocs.csv` (one row per IOC with source attribution)
- `intel/splunk_lookup_iocs.csv` (Splunk lookup format)
- `intel/iocs.json` (JSON)
- `intel/iocs.stix.json` (STIX 2.1 bundle)
- `intel/iocs.rss.xml` (RSS feed)
