<!-- curated:true -->
# [HIGH] FakeWallet Crypto Stealer Spreading Through iOS Apps in the App Store

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-20
**Article:** https://securelist.com/fakewallet-cryptostealer-ios-app-store/119474/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Kaspersky's Securelist team identified **20+ phishing apps in the Apple App Store** masquerading as legitimate crypto wallets (Trust Wallet, MetaMask, Phantom, Ledger, Exodus). Once launched, the apps **redirect users to lookalike "App Store" pages** that distribute trojanised wallet builds — bypassing Apple's review by fronting an innocent-looking app and switching content server-side post-install.

The campaign — **FakeWallet** — links to the broader **SparkKitty** infrastructure tracked by Kaspersky and is **multi-stage**:
1. Victim downloads the lookalike wallet app from the App Store.
2. The app redirects to attacker infrastructure that hands them a trojanised wallet binary (out-of-store sideload via configuration profile, or a fresh App Store app with the malicious config).
3. The trojanised wallet **collects mnemonic seed phrases / private keys** when the user "imports their wallet" or "creates a new one."
4. Keys are exfiltrated to attacker C2 over HTTPS (`hxxps://iosfc[.]com/ledger/ios/Rsakeycatch.php` etc.).

For enterprise SOCs, this isn't only a consumer-mobile issue:
- **Crypto-aware enterprise users** (treasury, finance ops, custody desks, crypto-services teams) are direct targets.
- **Personal-device-on-corporate-Wi-Fi** and **BYOD-MAM-managed** scenarios — the C2 traffic flows over your network even if the device isn't fully managed.
- The **lookalike-app-store / config-profile** pattern is **transferable** — same TTPs hit B2B fintech and corporate-banking apps.

We've kept severity **HIGH** because the **45 IOCs (1 IP + 24 domains + 21 MD5 hashes)** are immediately operational at the network layer.

## Indicators of Compromise (high-fidelity only)

- **IPv4:** `139.180.139.209`
- **24 defanged domains** including:
  - C2: `iosfc.com`, `appstoreios.com`, `crypto-stroe.cc`, `yjzhengruol.com`, `6688cf.jhxrpbgq.com`, `xz.apps-store.im`, `api.dc1637.xyz`
  - Subdomain-on-throwaway: `*.lahuafa.com`, `*.siyangoil.com`, `*.ahroar.com`, `*.oukwww.com`, `*.ulbcl.com`
  - Generic burner: `kkkhhhnnn.com`, `helllo2025.com`, `sxsfcc.com`, `nmu8n.com`, `zmx6f.com`
- **21 MD5 hashes** — see `intel/iocs.csv` (filter `sources=Securelist (Kaspersky)`).

## MITRE ATT&CK (analyst-validated)

- **T1656** — Impersonation (lookalike App Store / wallet brands)
- **T1583.001** — Acquire Infrastructure: Domains (cheap-TLD throwaways: `.cc`, `.xyz`, `.im`)
- **T1204.001 / T1204.002** — User Execution (malicious link / file)
- **T1071.001** — Application Layer Protocol: Web Protocols (HTTPS C2)
- **T1555** — Credentials from Password Stores (the wallet seeds)
- **T1657** — Financial Theft (cryptocurrency drainer endgame)
- **T1056.001** — Input Capture: Keylogging (in some FakeWallet variants)

## Recommended SOC actions (priority-ordered)

1. **Add the 24 domains + 1 IP to your DNS / proxy block list** today. Highest-leverage immediate action.
2. **Hunt 60 days of network logs** for any of these IOCs. Even a single resolution = potential personal compromise → pivot risk.
3. **Brief crypto-handling teams** (treasury, finance ops, custody, blockchain-engineering) — they're the targeted demographic. "Never re-enter your seed phrase into a wallet app you just downloaded."
4. **Block the lookalike-domain TLD pattern** (`*.cc`, `*.im`, `*.xyz` family) at egress for high-risk users where business-justifiable.
5. **MDM policy review** — if your iOS fleet allows arbitrary App Store installs, that's the dominant exposure surface; for high-risk roles, restrict to a curated app catalogue.
6. **Mobile-device-traffic visibility**: if BYOD doesn't route through corporate inspection, add corporate VPN or DNS-filter (Cloudflare Gateway / Cisco Umbrella) to extend coverage.

## Splunk SPL — DNS / web hits to FakeWallet IOCs

```spl
| tstats `summariesonly` count
    from datamodel=Network_Resolution.DNS
    where DNS.query IN (
        "iosfc.com","appstoreios.com","crypto-stroe.cc","yjzhengruol.com",
        "6688cf.jhxrpbgq.com","xz.apps-store.im","api.dc1637.xyz",
        "kkkhhhnnn.com","helllo2025.com","sxsfcc.com","nmu8n.com","zmx6f.com",
        "ntm0mdkzymy3n.oukwww.com","nziwytu5n.lahuafa.com","zdrhnmjjndu.ulbcl.com",
        "mti4ywy4.lahuafa.com","mtjln.siyangoil.com","odm0.siyangoil.com",
        "mgi1y.siyangoil.com","mziyytm5ytk.ahroar.com","ngy2yjq0otlj.ahroar.com",
        "api.npoint.io","www.gxzhrc.cn")
       OR DNS.query="*.lahuafa.com"
       OR DNS.query="*.siyangoil.com"
       OR DNS.query="*.ahroar.com"
       OR DNS.query="*.oukwww.com"
    by DNS.src, DNS.query, DNS.answer
| `drop_dm_object_name(DNS)`
| sort - count
```

## Splunk SPL — outbound to FakeWallet IP/domains (Web datamodel)

```spl
| tstats `summariesonly` count
    from datamodel=Web
    where Web.dest IN (
        "iosfc.com","appstoreios.com","crypto-stroe.cc","yjzhengruol.com",
        "api.dc1637.xyz","139.180.139.209")
       OR Web.url="*\.lahuafa\.com*"
       OR Web.url="*\.siyangoil\.com*"
       OR Web.url="*\.ahroar\.com*"
    by Web.src, Web.dest, Web.url, Web.user
| `drop_dm_object_name(Web)`
```

## Splunk SPL — file hash IOCs on managed endpoints

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN (
        "4126348d783393dd85ede3468e48405d","b639f7f81a8faca9c62fd227fef5e28c",
        "d48b580718b0e1617afc1dec028e9059","bafba3d044a4f674fc9edc67ef6b8a6b",
        "79fe383f0963ae741193989c12aefacc","8d45a67b648d2cb46292ff5041a5dd44",
        "7e678ca2f01dc853e85d13924e6c8a45","be9e0d516f59ae57f5553bcc3cf296d1",
        "fd0dc5d4bba740c7b4cc78c4b19a5840","7b4c61ff418f6fe80cf8adb474278311",
        "8cbd34393d1d54a90be3c2b53d8fc17a","d138a63436b4dd8c5a55d184e025ef99",
        "5bdae6cb778d002c806bb7ed130985f3","84c81a5e49291fe60eb9f5c1e2ac184b",
        "19733e0dfa804e3676f97eff90f2e467","8f51f82393c6467f9392fb9eb46f9301",
        "114721fbc23ff9d188535bd736a0d30e","686989d97cf0d70346cbde2031207cbf",
        "0565364633b5acdd24a498a6a9ab4eca","417ae7f384c49de8c672aec86d5a2860",
        "31d25ddf2697b9e13ee883fff328b22f")
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
```

## Defender KQL — DNS / network IOCs

```kql
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteIP =~ "139.180.139.209"
   or RemoteUrl has_any (
        "iosfc.com","appstoreios.com","crypto-stroe.cc","yjzhengruol.com",
        "api.dc1637.xyz","jhxrpbgq.com","apps-store.im","kkkhhhnnn.com",
        "helllo2025.com","sxsfcc.com","nmu8n.com","zmx6f.com",
        "lahuafa.com","siyangoil.com","ahroar.com","oukwww.com","ulbcl.com",
        "gxzhrc.cn","npoint.io")
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — file-hash match (managed endpoints)

```kql
let fakewalletHashes = dynamic([
    "4126348d783393dd85ede3468e48405d","b639f7f81a8faca9c62fd227fef5e28c",
    "d48b580718b0e1617afc1dec028e9059","bafba3d044a4f674fc9edc67ef6b8a6b",
    "79fe383f0963ae741193989c12aefacc","8d45a67b648d2cb46292ff5041a5dd44",
    "7e678ca2f01dc853e85d13924e6c8a45","be9e0d516f59ae57f5553bcc3cf296d1",
    "fd0dc5d4bba740c7b4cc78c4b19a5840","7b4c61ff418f6fe80cf8adb474278311",
    "8cbd34393d1d54a90be3c2b53d8fc17a","d138a63436b4dd8c5a55d184e025ef99",
    "5bdae6cb778d002c806bb7ed130985f3","84c81a5e49291fe60eb9f5c1e2ac184b",
    "19733e0dfa804e3676f97eff90f2e467","8f51f82393c6467f9392fb9eb46f9301",
    "114721fbc23ff9d188535bd736a0d30e","686989d97cf0d70346cbde2031207cbf",
    "0565364633b5acdd24a498a6a9ab4eca","417ae7f384c49de8c672aec86d5a2860",
    "31d25ddf2697b9e13ee883fff328b22f"]);
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(60d)
| where MD5 in~ (fakewalletHashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, MD5, ProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — crypto-wallet path access on Windows

```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where FolderPath has_any (
    "\\Exodus\\","\\Electrum\\","\\Atomic\\","\\MetaMask\\","\\Phantom\\",
    "\\Bitcoin\\","\\Ledger Live\\","\\Trust Wallet\\")
| where InitiatingProcessFileName !in~ (
    "Exodus.exe","Electrum.exe","Atomic.exe","MetaMask.exe","Phantom.exe",
    "bitcoin-qt.exe","Bitcoin Core.exe","Ledger Live.exe","Trust Wallet.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

FakeWallet is the latest worked example of a pattern that's now **endemic on iOS**: lookalike-app-as-redirector. Apple's review process catches the obvious; it doesn't catch apps that **appear benign at submission and switch content server-side post-install**. That cat-and-mouse game won't end soon.

For enterprise SOCs, three takeaways:
1. **Block the 24 domains + 1 IP at egress today.** Operational, vendor-attributed, free intel.
2. **The crypto-treasury / fintech corporate role profile is the target** — train and watch this user segment.
3. **Personal device traffic on corp infrastructure is your detection window** — the lookalike-app traffic flows over the same Wi-Fi as legitimate apps. DNS-layer visibility (Umbrella / Cloudflare Gateway / Quad9) extends your reach beyond MDM.

Pull the full IOC bundle from `intel/iocs.csv` (filter `sources=Securelist (Kaspersky)`) for the canonical list including hashes.
