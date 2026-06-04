# [LOW] Fake Claude Code Installer Via Google Sites Deliver Credential-Stealing Malware

**Source:** Cyber Security News
**Published:** 2026-06-04
**Article:** https://cybersecuritynews.com/fake-claude-code-installer-via-google-sites/

## Threat Profile

Cybercriminals have found a new and clever way to exploit the growing popularity of AI developer tools. A recently identified campaign uses fake pages mimicking Claude Code and OpenAI Codex, hosted on trusted Google Sites infrastructure, to trick users into running commands that quietly steal their credentials and other sensitive personal data from their devices. [&#8230;] The post Fake Claude Code Installer Via Google Sites Deliver Credential-Stealing Malware appeared first on Cyber Security Ne…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `145.249.109.147`
- **IPv4 (defanged):** `8.217.190.58`
- **IPv4 (defanged):** `109.107.170.111`
- **Domain (defanged):** `ravishingtattle.com`
- **Domain (defanged):** `claudedesktop-apps.squarespace.com`
- **Domain (defanged):** `claude-tool.squarespace.com`
- **Domain (defanged):** `claudesdesktop-apps.squarespace.com`
- **Domain (defanged):** `down-claave.squarespace.com`
- **Domain (defanged):** `claudemac.netlify.app`
- **Domain (defanged):** `claude-code-macos.framer.ai`
- **Domain (defanged):** `claude-code-das-pages.duckdns.org`
- **Domain (defanged):** `hyuzoa1-guboitzyasi.com`
- **Domain (defanged):** `claudiyoketka.com`
- **Domain (defanged):** `cludymians.com`
- **Domain (defanged):** `claudare.it.com`
- **Domain (defanged):** `myclaude.it.com`
- **Domain (defanged):** `clavdiydetka.com`
- **Domain (defanged):** `strangerwrought.com`
- **Domain (defanged):** `claude-desktop.github.io`
- **Domain (defanged):** `claude-deployer.github.io`
- **Domain (defanged):** `claude-mac-deployer.github.io`
- **Domain (defanged):** `claude-code-app.github.io`
- **Domain (defanged):** `claude-codex.github.io`
- **Domain (defanged):** `claude-deploy.github.io`
- **Domain (defanged):** `claude-desktop-macos.github.io`
- **Domain (defanged):** `claude-code-macos.github.io`
- **Domain (defanged):** `dn8xapil.in.net`
- **Domain (defanged):** `chinvuk1s.digital`
- **Domain (defanged):** `ctr.accrabbleshowm.cfd`
- **Domain (defanged):** `claude-code.official-version.com`
- **Domain (defanged):** `events.mn709.com`
- **Domain (defanged):** `claudecode-install.co.com`
- **Domain (defanged):** `claude-setup.com`
- **SHA256:** `2546a45f0e751dc02630ee48ae624f2cf536cbe1978122785e9d395c789c46c5`
- **SHA256:** `d04208c041891beac90d0ef818310c7bd98b66d7bdb3d2ba523fb1939915ac90`
- **SHA256:** `e1369e95f6e839c7b17d5a4209d6c5873cfaa3d9e469a4221938f4d449360dfd`
- **SHA256:** `363df5e77bc63ef323b136ea0b54e8e9f0469c0697e33cf8e326e2aa1cdc0c74`
- **SHA256:** `cda84f0339e834c1d23572acc52cc02747776cc52d6b63f6ace9ea72d80a835e`
- **SHA256:** `39ff5c82fce4e2d4a2b001fbfb2a4dd39ba4e11e88ef6844af4e2119b426b116`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `145.249.109.147`, `8.217.190.58`, `109.107.170.111`, `ravishingtattle.com`, `claudedesktop-apps.squarespace.com`, `claude-tool.squarespace.com`, `claudesdesktop-apps.squarespace.com`, `down-claave.squarespace.com` _(+25 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2546a45f0e751dc02630ee48ae624f2cf536cbe1978122785e9d395c789c46c5`, `d04208c041891beac90d0ef818310c7bd98b66d7bdb3d2ba523fb1939915ac90`, `e1369e95f6e839c7b17d5a4209d6c5873cfaa3d9e469a4221938f4d449360dfd`, `363df5e77bc63ef323b136ea0b54e8e9f0469c0697e33cf8e326e2aa1cdc0c74`, `cda84f0339e834c1d23572acc52cc02747776cc52d6b63f6ace9ea72d80a835e`, `39ff5c82fce4e2d4a2b001fbfb2a4dd39ba4e11e88ef6844af4e2119b426b116`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
