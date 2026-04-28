<!-- curated:true -->
# [MED] Weekly Recap: Vercel Hack, Push Fraud, QEMU Abused, New Android RATs Emerge & More

**Source:** The Hacker News
**Published:** 2026-04-20
**Article:** https://thehackernews.com/2026/04/weekly-recap-vercel-hack-push-fraud.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

A digest piece — covers several distinct stories in one post. Themes worth tagging:

1. **Vercel-style platform compromise** — third-party hosting / dev-platform breaches that pivot internal.
2. **Push-notification fraud** — adversary registers OAuth app or pushes web-push to harvest creds / interactions.
3. **QEMU abused** — adversaries running attacker-controlled VMs on victim hosts to evade EDR (continuation of the QEMU-as-LOLbin trend).
4. **New Android RATs** — typically banking malware piggybacking on accessibility services.

The "trust-bend" framing in the article is accurate: every item exploits an *expected* channel (third-party host, browser extension, vendor update, virtualisation tooling). Detection has to be **process-context** and **chain-anomaly** based, not perimeter.

We've kept severity **MED** because the article is a recap — individual stories merit their own briefings — but the queries below cover the broad detection backlog the recap implies.

## Indicators of Compromise

- _No specific IOCs from a recap article — each linked story has its own._
- The article is best read as a **detection-engineering checklist** rather than a hunt-on-IOCs list.

## MITRE ATT&CK (analyst-validated)

- **T1176** — Browser Extensions (Vercel/web-platform compromise pivoting via injected extensions)
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers (infostealer payloads)
- **T1497.003** — Virtualization/Sandbox Evasion: Time Based Evasion (QEMU runs)
- **T1564.006** — Hide Artifacts: Run Virtual Instance (QEMU LOLbin pattern)
- **T1567** — Exfiltration Over Web Service
- **T1195.002** — Compromise Software Supply Chain (the platform-compromise vector)

## Recommended SOC actions (priority-ordered)

1. **Run the browser-credential-store hunt below** — captures infostealer activity across Chrome / Edge / Firefox cookie + login databases. This is one of the highest-fidelity detections in the SOC arsenal; almost no legitimate non-browser process touches `Login Data` / `Cookies`.
2. **Hunt for QEMU / unusual hypervisor execution on user endpoints.** QEMU shouldn't run on most laptops outside engineering — when it does, it's almost always evasion tooling.
3. **Audit recent OAuth consent grants** in Entra/Okta — push-notification fraud frequently hides behind consented apps with `User.Read` + `Mail.Read` scopes.
4. **Review browser-extension changes on managed devices.** Cross-check with extensionmanagement enterprise policy.
5. **Look at outbound web traffic from your dev / engineering hosts to platform vendors (Vercel, Netlify, Cloudflare Pages, GitHub Pages)** — if your platform was compromised, your devs were the most likely victims.

## Splunk SPL — non-browser process accessing browser secret stores

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Login Data*"
        OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Cookies*"
        OR Filesystem.file_path="*\\Microsoft\\Edge\\User Data\\*\\Login Data*"
        OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*\\logins.json*"
        OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite*"
        OR Filesystem.file_path="*\\Brave\\User Data\\*\\Cookies*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                            "brave.exe","opera.exe","ssh-pageant.exe",
                                            "Update.exe","msiexec.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

## Splunk SPL — QEMU / VirtualBox / VMware execution from user endpoints

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("qemu-system-x86_64.exe","qemu-system-i386.exe",
                                       "qemu-system-aarch64.exe","qemu.exe",
                                       "VBoxHeadless.exe","VBoxManage.exe",
                                       "vmrun.exe","vmplayer.exe")
      AND NOT Processes.dest_category IN ("developer","engineering","sec-research")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — browser extension registry changes

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\\Software\\Google\\Chrome\\Extensions\\*"
        OR Registry.registry_path="*\\Software\\Microsoft\\Edge\\Extensions\\*"
        OR Registry.registry_path="*\\Software\\Mozilla\\Firefox\\Extensions\\*"
        OR Registry.registry_path="*\\Policies\\Google\\Chrome\\ExtensionInstallForcelist\\*")
      AND Registry.action IN ("modified","created")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data,
       Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

## Defender KQL — non-browser accessing browser secret stores

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("\\Google\\Chrome\\User Data\\",
                              "\\Microsoft\\Edge\\User Data\\",
                              "\\Mozilla\\Firefox\\Profiles\\",
                              "\\Brave\\User Data\\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite",
                       "Web Data","History")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe",
                                          "brave.exe","opera.exe","Update.exe","msiexec.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| order by Timestamp desc
```

## Defender KQL — QEMU / hypervisor execution

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("qemu-system-x86_64.exe","qemu-system-i386.exe",
                       "qemu-system-aarch64.exe","qemu.exe",
                       "VBoxHeadless.exe","VBoxManage.exe","vmrun.exe","vmplayer.exe")
| join kind=leftouter (DeviceInfo
    | where DeviceCategory !has_any ("developer","engineering","research")
    | project DeviceName) on DeviceName
| project Timestamp, DeviceName, DeviceCategory, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## Defender KQL — recent OAuth consent grants

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("Consent to application.","Add OAuth2PermissionGrant.")
| extend AppDisplayName = tostring(RawEventData.Target[0].ID),
         Permissions = tostring(RawEventData.ModifiedProperties[?Name=="ConsentAction.Permissions"].NewValue)
| where Permissions has_any ("Mail.Read","Mail.ReadWrite","Files.Read","Files.ReadWrite",
                              "User.Read","Directory.Read")
| project Timestamp, AccountObjectId, AccountDisplayName, AppDisplayName, Permissions, IPAddress
| order by Timestamp desc
```

## Why this matters for your SOC

Recap articles are useful as **a self-audit prompt** — for each item, ask: *"do we have a detection live for this?"* If you can answer yes for browser-stealer detection but no for QEMU LOLbin or OAuth-consent monitoring, that's your detection-engineering backlog for the quarter. The four patterns above are mid-2020s commodity intrusion shapes; the queries are bread-and-butter, not cutting-edge. Get them tuned and live before the next novel campaign uses the same TTPs.
