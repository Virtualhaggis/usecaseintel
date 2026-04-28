<!-- curated:true -->
# [HIGH] Cohere AI Terrarium Sandbox Flaw Enables Root Code Execution, Container Escape

**Source:** The Hacker News
**Published:** 2026-04-22
**Article:** https://thehackernews.com/2026/04/cohere-ai-terrarium-sandbox-flaw.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

**CVE-2026-5752** (CVSS **9.3**) is a sandbox escape in **Terrarium**, Cohere's Python sandbox used to safely run LLM-generated code. The escape works via **JavaScript prototype chain traversal** and grants **arbitrary root code execution on the host process** — i.e., container escape. This is the canonical "LLM-generated code runs in our sandbox so we're safe" failure mode.

Why this is a SOC problem, not just an AI/ML team problem:
- The Terrarium pattern (dynamic code-exec sandbox for LLM tool use) is being adopted everywhere — internal LLM agents, dev tools, RAG pipelines that execute generated code.
- The host process for the sandbox typically runs **as root inside the container**, and the container is usually colocated on inference infrastructure with model weights, embeddings, customer prompts, and downstream API keys.
- A working exploit lets an attacker turn any prompt-injection foothold into **host RCE on your inference fleet**.

We've upgraded severity to **HIGH** — combination of unauth-RCE-class via prompt injection + privileged execution + early-stage adoption of this sandbox class.

## Indicators of Compromise

- `CVE-2026-5752` — Terrarium sandbox escape
- Affected: Cohere Terrarium (specific version range — check Cohere advisory)
- Indirect risk: any project that vendored Terrarium or copied the JS-prototype-isolation pattern.

## MITRE ATT&CK (analyst-validated)

- **T1190** — Exploit Public-Facing Application (the LLM endpoint receiving the malicious prompt)
- **T1611** — Escape to Host (sandbox/container escape)
- **T1059.007** — JavaScript (prototype chain traversal)
- **T1059.006** — Python (the sandbox runtime)
- **T1068** — Exploitation for Privilege Escalation (root on host)
- **T1552.001** — Credentials In Files (post-escape: model/API keys, customer secrets)

## Recommended SOC actions (priority-ordered)

1. **Inventory every LLM agent / RAG pipeline that executes generated code.** Talk to ML platform teams. Ask specifically: *"do we run LLM-produced code in any sandbox?"* If the answer is "yes, Terrarium" or "yes, our own JS sandbox" — treat as exposed.
2. **Patch Terrarium to fixed version.** Re-deploy all containers. The fix has to ship with the model-serving infra, not just the application image.
3. **Reduce the blast radius.** The sandbox container should not run as root, should not have outbound network, should not have credentials available, should not share filesystem with the model-serving host.
4. **Hunt your inference hosts** for unexpected child processes, outbound connections, and `.so` / `.bin` writes from the sandbox runtime container.
5. **Audit prompt-injection logging.** If you don't capture full prompts (with PII redaction) on the inference path, you can't retroactively determine whether an attacker tried this exploit. Enable now.

## Splunk SPL — sandbox runtime spawning shells / network tools

```spl
| tstats `summariesonly` count min(_time) AS firstTime max(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("python","python3","node","node.exe",
                                              "terrarium","terrarium-runtime")
      AND Processes.process_name IN ("sh","bash","cmd.exe","curl","curl.exe","wget",
                                       "wget.exe","nc","ncat","busybox","sshd")
    by Processes.dest, Processes.user, Processes.parent_process_name,
       Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
```

## Splunk SPL — outbound from inference / ML hosts

```spl
| tstats `summariesonly` count
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src_category IN ("ai-ml","inference","llm","gpu-cluster")
      AND All_Traffic.action="allowed"
      AND All_Traffic.dest_category!="internal"
      AND All_Traffic.dest_category!="model-registry"
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| stats sum(count) AS sessions, dc(dest) AS unique_dests by src
| where unique_dests > 3
```

## Splunk SPL — credential reads on inference hosts

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.dest_category IN ("ai-ml","inference","llm")
      AND Filesystem.action="read"
      AND (Filesystem.file_name IN (".env","credentials","config.json","secrets.yaml")
        OR Filesystem.file_path="*.aws*"
        OR Filesystem.file_path="*.cohere*")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
```

## Defender KQL — Terrarium / sandbox child-process anomaly

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python","python3","node","node.exe","terrarium")
| where InitiatingProcessCommandLine has_any ("terrarium","sandbox","cohere")
| where FileName in~ ("sh","bash","cmd.exe","curl","wget","nc","ncat","busybox")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — vuln exposure

```kql
DeviceTvmSoftwareVulnerabilities
| where CveId =~ "CVE-2026-5752"
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```

## Defender KQL — outbound from ML/AI hosts

```kql
let aiHosts = DeviceInfo
    | where DeviceCategory has_any ("ai","ml","inference","gpu") or DeviceName has_any ("gpu-","inference-","llm-")
    | project DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceName in (aiHosts)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("python","python3","node","node.exe","sh","bash")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

The Terrarium pattern — *"we'll let the LLM run code, but in a sandbox"* — is now ubiquitous. Every framework that supports "tool use" or "code interpreter" is making the same bet, and nearly every implementation has the **same prototype-chain failure mode** waiting to be discovered. CVE-2026-5752 is **the first credible "prompt injection → host RCE" public exploit** of this class. Treat it as a template: the next one will hit your homegrown sandbox or whichever framework your team adopted last quarter. The defensive posture isn't "patch this CVE" — it's *"the sandbox is breakable, so make sure it has nothing worth stealing."* Inference containers should be ephemeral, unprivileged, network-segmented, credential-free.
