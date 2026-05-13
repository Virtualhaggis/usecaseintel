# [HIGH] PromptPwnd: Prompt Injection Vulnerabilities in GitHub Actions Using AI Agents

**Source:** Aikido
**Published:** 2025-12-04
**Article:** https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents

## Threat Profile

Blog Vulnerabilities & Threats PromptPwnd: Prompt Injection Vulnerabilities in GitHub Actions Using AI Agents PromptPwnd: Prompt Injection Vulnerabilities in GitHub Actions Using AI Agents Written by Rein Daelman Published on: Dec 4, 2025 Key takeaways Aikido Security discovered a new class of vulnerabilities, which we have named PromptPwnd, in GitHub Actions or GitLab CI/CD pipelines when combined with AI agents like Gemini CLI, Claude Code, OpenAI Codex, and GitHub AI Inference in CI/CD pipeli…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1567** — Exfiltration Over Web Service
- **T1059** — Command and Scripting Interpreter
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] AI agent token exfil via gh CLI issue/PR edit with embedded secret (PromptPwnd)

`UC_538_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="gh" OR Processes.process_name="gh.exe") (Processes.process="*issue edit*" OR Processes.process="*issue comment*" OR Processes.process="*issue create*" OR Processes.process="*pr edit*" OR Processes.process="*pr comment*" OR Processes.process="*pr create*") Processes.process="*--body*" (Processes.process="*ghp_*" OR Processes.process="*github_pat_*" OR Processes.process="*gho_*" OR Processes.process="*ghs_*" OR Processes.process="*ghu_*" OR Processes.process="*ghr_*" OR Processes.process="*AIza*" OR Processes.process="*ya29.*" OR Processes.process="*$GITHUB_TOKEN*" OR Processes.process="*$GEMINI_API_KEY*" OR Processes.process="*$GOOGLE_CLOUD_ACCESS_TOKEN*" OR Processes.process="*${GITHUB_TOKEN*" OR Processes.process="*${GEMINI_API_KEY*" OR Processes.process="*${GOOGLE_CLOUD_ACCESS_TOKEN*" OR Processes.process="*$ANTHROPIC_API_KEY*" OR Processes.process="*$OPENAI_API_KEY*") by host Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// PromptPwnd — gh CLI used to edit an issue/PR with a body that contains a token pattern
// or an unexpanded env-var token reference. Article (Aikido) shows the exact PoC on gemini-cli.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("gh", "gh.exe")
| where ProcessCommandLine has_any ("issue edit", "issue comment", "issue create", "pr edit", "pr comment", "pr create")
| where ProcessCommandLine has "--body"
| where ProcessCommandLine matches regex @"(?i)(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_\-]{30,}|ya29\.[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{20,}|\$\{?GITHUB_TOKEN\}?|\$\{?GEMINI_API_KEY\}?|\$\{?GOOGLE_CLOUD_ACCESS_TOKEN\}?|\$\{?ANTHROPIC_API_KEY\}?|\$\{?OPENAI_API_KEY\}?)"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] AI agent CLI on CI runner spawning shell that references token environment variables

`UC_538_4` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name="gemini" OR Processes.parent_process_name="gemini.exe" OR Processes.parent_process_name="claude" OR Processes.parent_process_name="claude.exe" OR Processes.parent_process_name="claude-code" OR Processes.parent_process_name="codex" OR Processes.parent_process_name="codex.exe") (Processes.process_name="bash" OR Processes.process_name="sh" OR Processes.process_name="zsh" OR Processes.process_name="pwsh" OR Processes.process_name="pwsh.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="cmd.exe" OR Processes.process_name="gh" OR Processes.process_name="gh.exe" OR Processes.process_name="curl" OR Processes.process_name="curl.exe" OR Processes.process_name="wget") (Processes.process="*GITHUB_TOKEN*" OR Processes.process="*GEMINI_API_KEY*" OR Processes.process="*GOOGLE_CLOUD_ACCESS_TOKEN*" OR Processes.process="*ANTHROPIC_API_KEY*" OR Processes.process="*OPENAI_API_KEY*" OR Processes.process="*GH_TOKEN*" OR Processes.process="*NPM_TOKEN*") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// AI agent process (gemini / claude / codex CLI) -> shell or HTTP/gh tool whose
// command line references a privileged token env var. Catches the article's
// run_shell_command(echo|gh issue ...) tool-call class beyond the gh-issue-edit PoC.
let _agent_parents = dynamic(["gemini","gemini.exe","claude","claude.exe","claude-code","claude-code.exe","codex","codex.exe"]);
let _exfil_children = dynamic(["bash","sh","zsh","dash","pwsh","pwsh.exe","powershell.exe","cmd.exe","gh","gh.exe","curl","curl.exe","wget","wget.exe"]);
let _privileged_envvars = dynamic(["GITHUB_TOKEN","GEMINI_API_KEY","GOOGLE_CLOUD_ACCESS_TOKEN","ANTHROPIC_API_KEY","OPENAI_API_KEY","GH_TOKEN","NPM_TOKEN","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (_agent_parents)
| where FileName in~ (_exfil_children)
| where ProcessCommandLine has_any (_privileged_envvars)
| project Timestamp, DeviceName, AccountName,
          AgentParent = InitiatingProcessFileName,
          AgentParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          Grandparent = InitiatingProcessParentFileName
| order by Timestamp desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
