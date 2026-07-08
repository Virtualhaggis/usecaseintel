# [HIGH] New Januscape Linux flaw allows VM escape on Intel, AMD devices

**Source:** BleepingComputer
**Published:** 2026-07-07
**Article:** https://www.bleepingcomputer.com/news/linux/new-januscape-linux-kernel-flaw-allows-vm-escape-on-intel-amd-devices/

## Threat Profile

New Januscape Linux flaw allows VM escape on Intel, AMD devices 
By Sergiu Gatlan 
July 7, 2026
08:06 AM
0 
A 16-year-old Linux kernel vulnerability, dubbed Januscape , allows attackers to escape a virtual machine and execute arbitrary code on the host.
According to Hyunwoo Kim, the security researcher who discovered it , this guest-to-host escape flaw (tracked as CVE-2026-53359 ) stems from a use-after-free weakness in the shadow MMU emulation of KVM/x86, the kernel-based virtual machine built …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-53359`
- **CVE:** `CVE-2026-43284`
- **CVE:** `CVE-2026-43500`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1611** — Escape to Host

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Non-virtualization process accessing /dev/kvm on KVM host (Januscape CVE-2026-53359 LPE precursor)

`UC_21_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*/dev/kvm*" AND NOT Processes.process_name IN ("qemu-system-x86_64","qemu-system-i386","qemu-kvm","qemu","libvirtd","virtqemud","cloud-hypervisor","firecracker","crosvm","kata-runtime","virt-host-validate","kvm-ok") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "/dev/kvm"
| where FileName !in~ ("qemu-system-x86_64","qemu-system-i386","qemu-kvm","qemu","libvirtd","virtqemud","cloud-hypervisor","firecracker","crosvm","kata-runtime","virt-host-validate","kvm-ok")
| where InitiatingProcessFileName !in~ ("libvirtd","virtqemud","systemd")
| where AccountName !in~ ("root","libvirt-qemu","qemu")   // world-writable /dev/kvm path is exploited by UNPRIVILEGED users
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### KVM/x86 hosts unpatched for Januscape CVE-2026-53359 and chained Dirty Frag CVEs

`UC_21_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-53359","CVE-2026-43284","CVE-2026-43500") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(3d)
| where CveId in ("CVE-2026-53359","CVE-2026-43284","CVE-2026-43500")
| where OSPlatform startswith "Linux"
| summarize arg_max(Timestamp, *) by DeviceName, CveId
| project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### Article-specific behavioural hunt — New Januscape Linux flaw allows VM escape on Intel, AMD devices

`UC_21_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Januscape Linux flaw allows VM escape on Intel, AMD devices ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/kvm*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Januscape Linux flaw allows VM escape on Intel, AMD devices
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/kvm"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-53359`, `CVE-2026-43284`, `CVE-2026-43500`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
