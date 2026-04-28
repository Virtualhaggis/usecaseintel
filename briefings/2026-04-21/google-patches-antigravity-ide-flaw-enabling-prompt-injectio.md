<!-- curated:true -->
# [MED] Google Patches Antigravity IDE Flaw Enabling Prompt Injection Code Execution

**Source:** The Hacker News
**Published:** 2026-04-21
**Article:** https://thehackernews.com/2026/04/google-patches-antigravity-ide-flaw.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Researchers found a code-execution flaw in **Google Antigravity**, an agentic AI IDE. The attack chain combines:
- Antigravity's permitted **file-creation** capability (an agent can write files into the workspace),
- with insufficient input sanitisation in the native `find_by_name` tool,
- to bypass **Strict mode** and achieve **arbitrary code execution** on the developer's host.

The route is **prompt-injection-via-content** — feed the IDE agent a doc/repo with carefully crafted text and it will silently execute code on your machine. Google has patched it.

This is the third "agentic IDE / sandbox → host RCE" story in two weeks (LeRobot, Cohere Terrarium, now Antigravity). The pattern is clear: **agentic tools that can write files + read the filesystem are 1-2 prompt-injection bugs away from RCE on every developer who uses them**.

## Indicators of Compromise

- No CVE assigned in the article excerpt — see Google security advisory or researcher write-up for the version range.
- Affected: Google Antigravity (versions prior to the patch).

## MITRE ATT&CK (analyst-validated)

- **T1059** — Command and Scripting Interpreter (the prompt-injection-driven exec)
- **T1204.002** — User Execution: Malicious File (developer opens / interacts with malicious content)
- **T1059.006** — Python (Antigravity tooling typically Python-driven)
- **T1027** — Obfuscated Files or Information (the injection payload typically encoded in benign-looking docs)

## Recommended SOC actions (priority-ordered)

1. **Inventory developer workstations with Antigravity installed** (or any agentic IDE — Cursor, Continue, Aider, Cline, etc.). Most SOCs have no idea which dev tools are in use.
2. **Force update to the patched Antigravity build.**
3. **Disable agent file-creation capability** in dev IDEs handling untrusted content (third-party repos, open-source PRs, customer-submitted code).
4. **Hunt developer endpoints for unexpected agent-spawned processes** — Python/Node spawning shells from a project workspace.
5. **Brief the dev community on prompt-injection-via-content.** Many devs paste long docs / repo files into agentic tools without realising the agent will *act* on the content.

## Splunk SPL — agentic-IDE child process anomaly on dev hosts

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where (Processes.parent_process_name IN ("antigravity","antigravity.exe","python","python.exe",
                                                "node","node.exe","cursor","cursor.exe","aider")
        OR Processes.process_path="*\\antigravity\\*"
        OR Processes.process_path="*\\Cursor\\*")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","bash","sh","curl","curl.exe",
                                       "wget","wget.exe","nc","ncat","certutil.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name,
       Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — file writes into project-workspace executables

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created"
      AND (Filesystem.file_name="*.sh" OR Filesystem.file_name="*.ps1"
        OR Filesystem.file_name="*.bat" OR Filesystem.file_name="*.cmd"
        OR Filesystem.file_name="*.py")
      AND Filesystem.process_name IN ("antigravity","antigravity.exe","python","node",
                                        "cursor","cursor.exe","aider")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

## Defender KQL — agentic IDE child-process anomaly

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where InitiatingProcessFileName in~ ("antigravity.exe","antigravity","cursor.exe",
                                         "python.exe","python","node.exe","node")
   or InitiatingProcessFolderPath has_any ("\\antigravity\\","\\Cursor\\","\\Continue\\")
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","curl.exe","wget.exe",
                       "nc.exe","certutil.exe","bitsadmin.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — file writes by agentic IDE outside dev-typical paths

```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("antigravity.exe","cursor.exe","python.exe","node.exe","aider")
| where FileName endswith ".sh" or FileName endswith ".ps1"
     or FileName endswith ".bat" or FileName endswith ".cmd"
| where FolderPath !has_any ("\\Projects\\",".venv\\","\\node_modules\\","\\test\\","\\tests\\")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

Agentic IDEs sit on **the most privileged endpoint your company owns**: a developer workstation with cloud creds, signing keys, source-tree write access, and direct production deploy paths. A prompt-injection RCE on a dev box isn't "we lost a laptop" — it's "the attacker is now committing code with valid signatures." The Antigravity flaw is patched, but the **pattern (capability tool + insufficient sanitisation = exec)** will recur across every agentic IDE for the foreseeable future. Build the detection logic now using the queries above; the next agentic-IDE RCE is a matter of weeks, not years.
