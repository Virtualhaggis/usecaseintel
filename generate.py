"""
Hacker News -> Splunk (CIM) + Microsoft Defender (KQL) use case generator.

Deeper analysis edition:
  - Rule engine maps article narrative to real attack patterns
  - Each pattern emits one or more UseCases with:
      * Splunk CIM `tstats` query against the right data model
      * Defender Advanced Hunting KQL against the right table
      * MITRE ATT&CK techniques + kill chain phase
      * "Why this fires" reasoning specific to the article
  - Per-article kill chain visualization (Lockheed 7 phases)
  - Inferred follow-on phases (attackers rarely stop at one stage)

Output: a single self-contained `index.html`.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import html
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import feedparser

# Sources & lookback configuration -------------------------------------------
LOOKBACK_DAYS = 36500     # ~100 years — effectively no rolling window.
                          # The user wants every article we've ever pulled to
                          # stay on the live site, never age off. Subsequent
                          # runs use the per-URL caches so re-runs are cheap;
                          # LLM bespoke UCs cost only on first encounter.
                          # NB: site page weight grows over time — at ~430
                          # articles we're already at 17 MB (Google's hard
                          # indexing cap is ~15 MB). When this becomes a
                          # ranking issue, switch to lazy-loading older
                          # articles into a separate "Archive" view rather
                          # than dropping them.
MAX_PER_SOURCE = 500      # safety cap per source per run

SOURCES = [
    # News-style sources — broad coverage, light on IOC tables.
    {"name": "The Hacker News",        "kind": "rss",
     "url":  "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer",        "kind": "rss",
     "url":  "https://www.bleepingcomputer.com/feed/"},
    {"name": "Microsoft Security Blog", "kind": "rss",
     "url":  "https://www.microsoft.com/en-us/security/blog/feed/"},
    # Vendor research blogs — heavy IOC content (hashes, defanged IPs, domains
    # in the article body). These are the primary feeders of the IOC export.
    {"name": "Cisco Talos",             "kind": "rss",
     "url":  "https://blog.talosintelligence.com/rss/"},
    {"name": "Securelist (Kaspersky)",  "kind": "rss",
     "url":  "https://securelist.com/feed/"},
    {"name": "SentinelLabs",            "kind": "rss",
     "url":  "https://www.sentinelone.com/labs/feed/"},
    {"name": "Unit 42 (Palo Alto)",     "kind": "rss",
     "url":  "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "ESET WeLiveSecurity",     "kind": "rss",
     "url":  "https://www.welivesecurity.com/en/rss/feed/"},
    # Lab52 — threat-intel research arm of S2 Grupo. Heavy on APT
    # write-ups (RU/CN/MENA actors) with rich IOC tables and YARA.
    {"name": "Lab52",                   "kind": "rss",
     "url":  "https://lab52.io/blog/feed/"},
    # Cyber Security News — broad daily feed; complements the news-
    # style sources with extra coverage on emerging CVEs and POCs.
    {"name": "Cyber Security News",     "kind": "rss",
     "url":  "https://cybersecuritynews.com/feed/"},
    # Supply-chain / open-source ecosystem researchers — fill the gap left
    # by news outlets when a campaign breaks across npm / PyPI / GitHub
    # Actions (Snyk + Aikido covered TanStack / Mini Shai-Hulud first;
    # StepSecurity routinely publishes named-actor attribution).
    {"name": "Snyk",                    "kind": "rss",
     "url":  "https://snyk.io/blog/feed/"},
    {"name": "Aikido",                  "kind": "rss",
     "url":  "https://www.aikido.dev/blog/rss.xml"},
    {"name": "StepSecurity",            "kind": "rss",
     "url":  "https://www.stepsecurity.io/blog/rss.xml"},
    # Authoritative exploited-vuln feed.
    {"name": "CISA KEV",                "kind": "kev",
     "url":  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    # GitHub Security Advisories — authoritative, reviewed entries for the
    # entire open-source ecosystem (npm / PyPI / Maven / RubyGems / Go /
    # Cargo / NuGet / Composer). REST API only — the github.com/advisories
    # atom endpoint server-side rejects non-pjax requests with 406. Caught
    # the TanStack / Mini Shai-Hulud advisory (CVE-2026-45321) within
    # minutes of publication, hours before vendor blogs picked it up.
    {"name": "GitHub Security Advisories", "kind": "ghsa",
     "url":  "https://api.github.com/advisories?type=reviewed&severity=critical&per_page=100&sort=published"},
]

# Legacy (kept for callers using the old API)
RSS_URL = SOURCES[0]["url"]
ARTICLE_LIMIT = 10
OUT_HTML = Path(__file__).with_name("index.html")


# =============================================================================
# Indicator extraction (atomic IOCs from the limited RSS summary)
# =============================================================================

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
HASH_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
HASH_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
HASH_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Defanged-only IOC extraction. Plain text "outlook.com" or "1.2.3.4" mentioned
# casually in an article summary is NOT a SOC-grade indicator — those are
# almost always legitimate platforms or victim infrastructure. We only accept
# domain/IP IOCs when the source author has *defanged* them with bracketed
# dots (`evil[.]com`, `1[.]2[.]3[.]4`) or `hxxp(s)://` — the universal
# convention for "this is malicious; don't auto-click".
# IPv4 forms: defanged ("1[.]2[.]3[.]4") and the variant with three defangs and
# one literal dot (sometimes seen in vendor write-ups, e.g. "139.180.139[.]209")
DEFANGED_IPV4_RE = re.compile(
    r"\b("
    r"(?:\d{1,3}\[\.\]){3}\d{1,3}"
    r"|"
    r"(?:\d{1,3}\.){2}\d{1,3}\[\.\]\d{1,3}"
    r"|"
    r"\d{1,3}\.\d{1,3}\[\.\]\d{1,3}\.\d{1,3}"
    r"|"
    r"\d{1,3}\[\.\]\d{1,3}\.\d{1,3}\.\d{1,3}"
    r")\b"
)
# Domain: 2+ labels with at least one `[.]` separator, ending in 2+-char TLD.
DEFANGED_DOMAIN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:(?:\[\.\]|\.)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\[\.\][a-z]{2,})\b",
    re.IGNORECASE,
)
# hxxp(s):// URL — capture host+path. Critically, allow `[.]` (defang) inside.
HXXP_URL_RE = re.compile(
    r"hxxps?://([a-z0-9.\-]+(?:\[\.\][a-z0-9.\-]+)*\[\.\][a-z]{2,}(?:/[^\s\"'<>]*)?)",
    re.IGNORECASE,
)


def _refang(s):
    """Convert defanged IOC back to canonical form for downstream tooling."""
    return (s.replace("[.]", ".").replace("[:]", ":")
             .replace("hxxp://", "http://").replace("hxxps://", "https://"))


def strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s or "")


def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        k = x.lower() if isinstance(x, str) else x
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


# =====================================================================
# Threat-actor catalog
# =====================================================================
# Curated list of well-known APT / e-crime / ransomware groups with
# country attribution. Aliases come from MITRE ATT&CK Groups, Mandiant,
# CrowdStrike (Bears/Pandas/Cobras), Microsoft Threat Intel (Typhoons /
# Sleet / Blizzard naming convention) and Unit 42.
# Match against article body via case-insensitive whole-word regex;
# the longest alias wins so "APT29" and "Midnight Blizzard" both
# resolve to the same canonical name.
# Country uses ISO 3166-2 alpha-2 + flag emoji for compact rendering.
# Motivation: state | criminal | hacktivist | unknown.
THREAT_ACTORS = [
    # ===== Russia =====
    {"name": "APT28", "aliases": ["APT28", "Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Forest Blizzard", "Pawn Storm", "Tsar Team", "GRU Unit 26165"], "country": "RU", "flag": "🇷🇺", "motivation": "state", "mitre_id": "G0007"},
    {"name": "APT29", "aliases": ["APT29", "Cozy Bear", "Nobelium", "Midnight Blizzard", "The Dukes", "YTTRIUM", "SVR"], "country": "RU", "flag": "🇷🇺", "motivation": "state", "mitre_id": "G0016"},
    {"name": "Sandworm", "aliases": ["Sandworm", "Voodoo Bear", "TeleBots", "BlackEnergy Group", "Iron Viking", "Seashell Blizzard", "GRU Unit 74455"], "country": "RU", "flag": "🇷🇺", "motivation": "state", "mitre_id": "G0034"},
    {"name": "Turla", "aliases": ["Turla", "Snake", "Venomous Bear", "Waterbug", "Uroburos", "Krypton", "Secret Blizzard"], "country": "RU", "flag": "🇷🇺", "motivation": "state", "mitre_id": "G0010"},
    {"name": "Gamaredon", "aliases": ["Gamaredon", "Primitive Bear", "Shuckworm", "Aqua Blizzard", "Armageddon", "Trident Ursa"], "country": "RU", "flag": "🇷🇺", "motivation": "state", "mitre_id": "G0047"},
    {"name": "Berserk Bear", "aliases": ["Berserk Bear", "Energetic Bear", "DragonFly", "Crouching Yeti", "Iron Liberty"], "country": "RU", "flag": "🇷🇺", "motivation": "state", "mitre_id": "G0035"},
    {"name": "Cadet Blizzard", "aliases": ["Cadet Blizzard", "Ember Bear", "Saint Bear", "UAC-0056"], "country": "RU", "flag": "🇷🇺", "motivation": "state", "mitre_id": "G1003"},

    # ===== China =====
    {"name": "APT41", "aliases": ["APT41", "BARIUM", "Wicked Panda", "Winnti Group", "Brass Typhoon", "Double Dragon"], "country": "CN", "flag": "🇨🇳", "motivation": "state", "mitre_id": "G0096"},
    {"name": "APT10", "aliases": ["APT10", "Stone Panda", "MenuPass", "Cloudhopper", "Potassium", "Bronze Riverside"], "country": "CN", "flag": "🇨🇳", "motivation": "state", "mitre_id": "G0045"},
    {"name": "Volt Typhoon", "aliases": ["Volt Typhoon", "Vanguard Panda", "Bronze Silhouette", "VOLTZITE", "BRONZE SILHOUETTE"], "country": "CN", "flag": "🇨🇳", "motivation": "state", "mitre_id": "G1017"},
    {"name": "Salt Typhoon", "aliases": ["Salt Typhoon", "GhostEmperor", "FamousSparrow", "Earth Estries"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "Silk Typhoon", "aliases": ["Silk Typhoon", "Hafnium", "Operation Exchange Marauder"], "country": "CN", "flag": "🇨🇳", "motivation": "state", "mitre_id": "G0125"},
    {"name": "Mustang Panda", "aliases": ["Mustang Panda", "TA416", "RedDelta", "Earth Preta", "Bronze President", "Stately Taurus"], "country": "CN", "flag": "🇨🇳", "motivation": "state", "mitre_id": "G0129"},
    {"name": "Storm-0558", "aliases": ["Storm-0558"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "PlushDaemon", "aliases": ["PlushDaemon"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "LongNoseGoblin", "aliases": ["LongNoseGoblin", "Long-Nose Goblin"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "GALLIUM", "aliases": ["GALLIUM", "Operation Soft Cell", "Granite Typhoon"], "country": "CN", "flag": "🇨🇳", "motivation": "state", "mitre_id": "G0093"},
    {"name": "TA413", "aliases": ["TA413", "LuckyCat", "Tropic Trooper"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "APT3", "aliases": ["APT3", "Gothic Panda", "UPS Team", "Boyusec"], "country": "CN", "flag": "🇨🇳", "motivation": "state", "mitre_id": "G0022"},

    # ===== North Korea =====
    {"name": "Lazarus Group", "aliases": ["Lazarus", "Lazarus Group", "Hidden Cobra", "Guardians of Peace", "ZINC", "Diamond Sleet", "Labyrinth Chollima"], "country": "KP", "flag": "🇰🇵", "motivation": "state", "mitre_id": "G0032"},
    {"name": "Kimsuky", "aliases": ["Kimsuky", "Velvet Chollima", "Black Banshee", "Thallium", "Emerald Sleet"], "country": "KP", "flag": "🇰🇵", "motivation": "state", "mitre_id": "G0094"},
    {"name": "APT38", "aliases": ["APT38", "BeagleBoyz", "Stardust Chollima"], "country": "KP", "flag": "🇰🇵", "motivation": "state", "mitre_id": "G0082"},
    {"name": "Andariel", "aliases": ["Andariel", "Silent Chollima", "Onyx Sleet"], "country": "KP", "flag": "🇰🇵", "motivation": "state", "mitre_id": "G0138"},
    {"name": "Bluenoroff", "aliases": ["Bluenoroff", "Sapphire Sleet", "TA444"], "country": "KP", "flag": "🇰🇵", "motivation": "state", "mitre_id": "G0098"},
    {"name": "APT37", "aliases": ["APT37", "ScarCruft", "Reaper", "InkySquid", "Ricochet Chollima"], "country": "KP", "flag": "🇰🇵", "motivation": "state", "mitre_id": "G0067"},
    {"name": "Moonstone Sleet", "aliases": ["Moonstone Sleet", "Storm-1789"], "country": "KP", "flag": "🇰🇵", "motivation": "state"},

    # ===== Iran =====
    {"name": "APT34", "aliases": ["APT34", "OilRig", "Helix Kitten", "Cobalt Gypsy", "Hazel Sandstorm"], "country": "IR", "flag": "🇮🇷", "motivation": "state", "mitre_id": "G0049"},
    {"name": "APT35", "aliases": ["APT35", "Charming Kitten", "Phosphorus", "Mint Sandstorm", "Newscaster", "Magic Hound"], "country": "IR", "flag": "🇮🇷", "motivation": "state", "mitre_id": "G0059"},
    {"name": "APT33", "aliases": ["APT33", "Refined Kitten", "Elfin", "Holmium", "Peach Sandstorm"], "country": "IR", "flag": "🇮🇷", "motivation": "state", "mitre_id": "G0064"},
    {"name": "MuddyWater", "aliases": ["MuddyWater", "Earth Vetala", "MERCURY", "Static Kitten", "Mango Sandstorm", "TEMP.Zagros", "Seedworm"], "country": "IR", "flag": "🇮🇷", "motivation": "state", "mitre_id": "G0069"},
    {"name": "Imperial Kitten", "aliases": ["Imperial Kitten", "Tortoiseshell", "TA456"], "country": "IR", "flag": "🇮🇷", "motivation": "state", "mitre_id": "G1010"},
    {"name": "APT39", "aliases": ["APT39", "Chafer", "Remix Kitten"], "country": "IR", "flag": "🇮🇷", "motivation": "state", "mitre_id": "G0087"},

    # ===== Vietnam / SEA =====
    {"name": "APT32", "aliases": ["APT32", "OceanLotus", "SeaLotus", "Cobalt Kitty"], "country": "VN", "flag": "🇻🇳", "motivation": "state", "mitre_id": "G0050"},

    # ===== Pakistan / India =====
    {"name": "Transparent Tribe", "aliases": ["Transparent Tribe", "APT36", "Mythic Leopard", "Operation C-Major"], "country": "PK", "flag": "🇵🇰", "motivation": "state", "mitre_id": "G0134"},
    {"name": "Patchwork", "aliases": ["Patchwork", "Dropping Elephant", "Chinastrats", "Quilted Tiger"], "country": "IN", "flag": "🇮🇳", "motivation": "state", "mitre_id": "G0040"},
    {"name": "SideWinder", "aliases": ["SideWinder", "RattleSnake", "Razor Tiger", "T-APT-04"], "country": "IN", "flag": "🇮🇳", "motivation": "state", "mitre_id": "G0121"},

    # ===== Ransomware groups (criminal, multi-national) =====
    {"name": "LockBit", "aliases": ["LockBit", "LockBit 2.0", "LockBit 3.0", "LockBit Black", "LockBit Green", "LockBit 5.0"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "BlackCat", "aliases": ["BlackCat", "ALPHV", "ALPHV-BlackCat", "Noberus"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "Conti", "aliases": ["Conti", "Wizard Spider", "TrickBot Group", "GOLD ULRICK"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal", "mitre_id": "G0102"},
    {"name": "REvil", "aliases": ["REvil", "Sodinokibi", "GOLD SOUTHFIELD", "Pinchy Spider"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal", "mitre_id": "G0115"},
    {"name": "Cl0p", "aliases": ["Cl0p", "Clop", "TA505", "FIN11", "GRACEFUL SPIDER"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal", "mitre_id": "G0092"},
    {"name": "Black Basta", "aliases": ["Black Basta", "BlackBasta"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "Royal", "aliases": ["Royal Ransomware", "DEV-0569"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "Akira", "aliases": ["Akira ransomware", "Akira"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Play", "aliases": ["Play ransomware", "PlayCrypt", "Balloonfly"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "Qilin", "aliases": ["Qilin", "Agenda ransomware"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "Medusa", "aliases": ["Medusa ransomware", "MedusaLocker"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "8Base", "aliases": ["8Base ransomware", "8Base"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "RansomHub", "aliases": ["RansomHub"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "DragonForce", "aliases": ["DragonForce", "DragonForce Malaysia"], "country": "MY", "flag": "🇲🇾", "motivation": "criminal"},
    {"name": "Hunters International", "aliases": ["Hunters International"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Rhysida", "aliases": ["Rhysida"], "country": "??", "flag": "🌐", "motivation": "criminal"},

    # ===== eCrime / IAB =====
    {"name": "Scattered Spider", "aliases": ["Scattered Spider", "0ktapus", "UNC3944", "Octo Tempest", "Muddled Libra", "Roasted 0ktapus", "Storm-0875"], "country": "US", "flag": "🇺🇸", "motivation": "criminal", "mitre_id": "G1015"},
    {"name": "FIN7", "aliases": ["FIN7", "Carbanak Group", "Sangria Tempest", "ITG14"], "country": "??", "flag": "🌐", "motivation": "criminal", "mitre_id": "G0046"},
    {"name": "FIN6", "aliases": ["FIN6", "Skeleton Spider", "Camouflage Tempest", "ITG08"], "country": "??", "flag": "🌐", "motivation": "criminal", "mitre_id": "G0037"},
    {"name": "FIN8", "aliases": ["FIN8", "Syssphinx"], "country": "??", "flag": "🌐", "motivation": "criminal", "mitre_id": "G0061"},
    {"name": "Cobalt Group", "aliases": ["Cobalt Group", "Cobalt Gang", "Cobalt Spider", "GOLD KINGSWOOD"], "country": "??", "flag": "🌐", "motivation": "criminal", "mitre_id": "G0080"},
    {"name": "TA577", "aliases": ["TA577", "Hive0118"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "TA571", "aliases": ["TA571"], "country": "??", "flag": "🌐", "motivation": "criminal"},

    # ===== South America =====
    {"name": "Lapsus$", "aliases": ["Lapsus$", "DEV-0537", "Strawberry Tempest"], "country": "BR", "flag": "🇧🇷", "motivation": "criminal", "mitre_id": "G1004"},

    # ===== Iran (additional) =====
    {"name": "Pioneer Kitten", "aliases": ["Pioneer Kitten", "FOX KITTEN", "PARISITE", "Lemon Sandstorm"], "country": "IR", "flag": "🇮🇷", "motivation": "state"},
    {"name": "Cyber Av3ngers", "aliases": ["Cyber Av3ngers", "CyberAvengers", "IRGC-CEC"], "country": "IR", "flag": "🇮🇷", "motivation": "hacktivist"},

    # ===== Russia (additional) =====
    {"name": "BianLian", "aliases": ["BianLian"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "BlackByte", "aliases": ["BlackByte", "Blackbyte"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "TA505", "aliases": ["TA505", "Hive0065", "Evil Corp", "Indrik Spider", "GOLD DRAKE"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal", "mitre_id": "G0092"},
    {"name": "TA570", "aliases": ["TA570"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},

    # ===== China (additional) =====
    {"name": "Earth Lusca", "aliases": ["Earth Lusca", "TAG-22", "Aquatic Panda", "Bronze University"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "MirrorFace", "aliases": ["MirrorFace", "Cuckoo Spear", "Earth Kasha"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "Storm-2077", "aliases": ["Storm-2077"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "Brass Typhoon", "aliases": ["Brass Typhoon"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "Flax Typhoon", "aliases": ["Flax Typhoon", "Ethereal Panda"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "Linen Typhoon", "aliases": ["Linen Typhoon"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},
    {"name": "Granite Typhoon", "aliases": ["Granite Typhoon"], "country": "CN", "flag": "🇨🇳", "motivation": "state"},

    # ===== Newer ransomware crews =====
    {"name": "Hellcat", "aliases": ["Hellcat ransomware", "Hellcat"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Embargo", "aliases": ["Embargo ransomware", "Embargo group"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "INC Ransom", "aliases": ["INC ransomware", "INC Ransom", "INC Group"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Stormous", "aliases": ["Stormous"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Trinity ransomware", "aliases": ["Trinity ransomware"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Brain Cipher", "aliases": ["Brain Cipher ransomware", "BrainCipher"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Termite", "aliases": ["Termite ransomware"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Kairos", "aliases": ["Kairos ransomware"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Funksec", "aliases": ["Funksec", "FunkSec"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Killsec", "aliases": ["KillSec"], "country": "??", "flag": "🌐", "motivation": "criminal"},

    # ===== Additional e-crime / IAB =====
    {"name": "Wizard Spider", "aliases": ["Wizard Spider", "GOLD BLACKBURN", "ITG23"], "country": "RU", "flag": "🇷🇺", "motivation": "criminal"},
    {"name": "TA571", "aliases": ["TA571"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "TA582", "aliases": ["TA582"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Storm-1849", "aliases": ["Storm-1849"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Storm-1811", "aliases": ["Storm-1811"], "country": "??", "flag": "🌐", "motivation": "criminal"},
    {"name": "Storm-1567", "aliases": ["Storm-1567"], "country": "??", "flag": "🌐", "motivation": "criminal"},

    # ===== North Korea (additional) =====
    {"name": "Citrine Sleet", "aliases": ["Citrine Sleet", "DEV-0139", "DEV-1222", "AppleJeus", "Labyrinth Chollima Citrine"], "country": "KP", "flag": "🇰🇵", "motivation": "state"},
    {"name": "Famous Chollima", "aliases": ["Famous Chollima"], "country": "KP", "flag": "🇰🇵", "motivation": "state"},

    # ===== MENA / Lebanon =====
    {"name": "Volatile Cedar", "aliases": ["Volatile Cedar", "Lebanese Cedar"], "country": "LB", "flag": "🇱🇧", "motivation": "state"},
]

# Build alias→canonical lookup once at import; precompile a single
# regex covering every alias (longest-first so a longer alias is
# preferred over a substring match — e.g. "APT29" wins over "APT").
import re as _actor_re
_ALIAS_TO_NAME = {a.lower(): tg["name"] for tg in THREAT_ACTORS for a in tg["aliases"]}
_ACTOR_PATTERN = _actor_re.compile(
    r"\b(?:" + "|".join(
        _actor_re.escape(a) for a in sorted(_ALIAS_TO_NAME.keys(), key=len, reverse=True)
    ) + r")\b",
    flags=_actor_re.IGNORECASE,
)
_ACTOR_BY_NAME = {tg["name"]: tg for tg in THREAT_ACTORS}


def extract_threat_actors(title: str, body: str) -> list:
    """Return the list of canonical actor names mentioned in the
    article. Case-insensitive substring match against the curated
    alias list. De-duped, ordered by first appearance.
    Empty list if no known actor is mentioned."""
    text = f"{title}\n\n{body or ''}"
    seen = []
    for m in _ACTOR_PATTERN.finditer(text):
        canonical = _ALIAS_TO_NAME.get(m.group(0).lower())
        if canonical and canonical not in seen:
            seen.append(canonical)
    return seen


def extract_indicators(title: str, body: str) -> dict:
    """
    SOC-grade IOC extraction. Quality bar:
      - CVE: regex match (unambiguous format, low FP rate)
      - Hash (MD5/SHA1/SHA256): regex match (high entropy, low FP rate)
      - Domain/IP: ONLY accept defanged forms (`evil[.]com`, `1[.]2[.]3[.]4`,
        `hxxps://...`). Plain-text mentions are almost always legitimate
        infrastructure (the victim, the platform, the security vendor),
        so they're rejected. This means article summaries that don't use
        defanged notation will produce zero domain/IP IOCs — which is the
        correct behaviour for a feed an analyst will block on.
    """
    text = f"{title}\n{body}"

    # Defanged IPs — high-confidence
    ips = dedupe(_refang(m.group(1)) for m in DEFANGED_IPV4_RE.finditer(text))

    # Defanged domains and hxxp:// URLs — extract host part of URLs
    domains = []
    for m in DEFANGED_DOMAIN_RE.finditer(text):
        domains.append(_refang(m.group(1)).lower())
    for m in HXXP_URL_RE.finditer(text):
        url_host = _refang(m.group(1)).split("/", 1)[0].lower()
        domains.append(url_host)
    domains = dedupe(domains)

    # ---- Quality filter: drop legitimate-platform / reserved IOCs ----
    # No SOC wants `google.com` or `8.8.8.8` blocked. These domains/IPs
    # appear in articles as legitimate context (the platform an attack
    # abused, the example DNS the malware queried, the victim site, etc.)
    # and should never make it to the IOC feed. Keep this list narrow:
    # only domains/IPs that are universally trusted infrastructure.
    domains = [d for d in domains if not _ioc_is_known_safe(d, kind="domain")]
    ips = [i for i in ips if not _ioc_is_known_safe(i, kind="ipv4")]

    return {
        "cves": dedupe(CVE_RE.findall(text)),
        "ips": ips,
        "domains": domains,
        "md5": dedupe(HASH_MD5_RE.findall(text)),
        "sha1": dedupe(HASH_SHA1_RE.findall(text)),
        "sha256": dedupe(HASH_SHA256_RE.findall(text)),
        "explicit_ttps": dedupe(ATTACK_RE.findall(text)),
    }


# Curated allowlist of legitimate-platform infrastructure. An article that
# mentions "the malware downloaded a file from google.com" doesn't mean we
# should ship google.com as an IOC — it's the dispenser, not the threat.
# Keep this list as small as possible; over-blocking risks dropping a real
# typosquat. Only include domains that NO real adversary would register.
_IOC_DOMAIN_ALLOWLIST = {
    # Mainstream user platforms
    "google.com", "www.google.com", "gmail.com", "youtube.com", "blogspot.com",
    "microsoft.com", "www.microsoft.com", "live.com", "outlook.com", "office.com",
    "office365.com", "onmicrosoft.com", "msn.com", "bing.com", "msftauth.net",
    "azure.com", "azurewebsites.net", "windows.net", "sharepoint.com",
    "apple.com", "icloud.com", "me.com", "mac.com", "appstoreios.apple.com",
    "amazon.com", "aws.amazon.com", "amazonaws.com", "amazonses.com",
    "cloudflare.com", "cloudflare-dns.com", "cdnjs.cloudflare.com",
    "adobe.com", "adobeid.com", "creativecloud.adobe.com",
    # Major enterprise / chip / hardware vendors — legitimate platforms
    # that show up in articles as victim or context, never as adversary
    # infrastructure. Subdomain-match strips e.g. "support.cisco.com".
    "intel.com", "amd.com", "nvidia.com", "qualcomm.com", "broadcom.com", "arm.com",
    "ibm.com", "redhat.com", "oracle.com", "sap.com", "sap.de",
    "vmware.com", "citrix.com",
    "cisco.com", "fortinet.com", "paloaltonetworks.com", "checkpoint.com",
    "dell.com", "hp.com", "hpe.com", "lenovo.com", "samsung.com", "sony.com",
    # SaaS platforms with enormous legitimate user bases
    "salesforce.com", "force.com", "salesforce-experience.com",
    "zendesk.com", "hubspot.com", "intercom.com", "zoom.us",
    "slack.com", "discord.com", "telegram.org",
    "dropbox.com", "box.com", "wetransfer.com",
    # Document signing / e-sign platforms
    "docusign.com", "docusign.net", "echosign.com", "adobe-sign.com",
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "twitter.com",
    "x.com", "linkedin.com", "reddit.com", "pinterest.com", "tiktok.com",
    # Dev / package ecosystems
    "github.com", "api.github.com", "raw.githubusercontent.com", "githubusercontent.com",
    "gist.github.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org", "atlassian.net", "atlassian.com",
    "npmjs.org", "registry.npmjs.org", "yarnpkg.com", "pnpm.io",
    "pypi.org", "pythonhosted.org", "anaconda.org", "conda.anaconda.org",
    "rubygems.org", "crates.io", "packagist.org", "nuget.org",
    "docker.io", "hub.docker.com", "gcr.io", "ghcr.io", "quay.io", "mcr.microsoft.com",
    # Open-source / docs / standards
    "wikipedia.org", "stackoverflow.com", "stackexchange.com",
    "medium.com", "dev.to", "hackernoon.com",
    "rfc-editor.org", "ietf.org", "w3.org", "iana.org",
    "mozilla.org", "owasp.org",
    # Security-research / vendor reference (shouldn't be IOCs even when cited)
    "mitre.org", "attack.mitre.org", "cve.mitre.org", "nvd.nist.gov", "cisa.gov",
    "thehackernews.com", "bleepingcomputer.com", "krebsonsecurity.com",
    "talosintelligence.com", "blog.talosintelligence.com",
    "securelist.com", "sentinelone.com", "unit42.paloaltonetworks.com",
    "welivesecurity.com", "lab52.io", "cybersecuritynews.com",
    "checkmarx.com", "snyk.io", "socket.dev", "aikido.dev", "stepsecurity.io",
    "virustotal.com", "abuse.ch", "urlhaus.abuse.ch", "threatfox.abuse.ch",
    # Common legit dispensers (ARTICLE-CONTEXT only — these CAN be abused as
    # dead-drops by malware. We drop them from the IOC feed because alerting
    # on every pastebin URL would drown the SOC; analysts hunt these manually.)
    "pastebin.com", "ghostbin.com", "rentry.co", "snippet.host",
    # Generic test / example
    "example.com", "example.net", "example.org", "example.invalid",
    "localhost", "test.com", "yourorganisation.com",
    # Sample-data junk we've seen previously extracted
    "xxx.com", "appstoreios", "iosfc",
}

# Block IPv4s that are universally trusted, reserved, or non-routable.
def _is_reserved_or_safe_ipv4(ip: str) -> bool:
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
    except Exception:
        return True  # malformed → treat as safe (drop)
    if a == 0:        return True   # 0.0.0.0/8
    if a == 10:       return True   # RFC1918
    if a == 127:      return True   # loopback
    if a == 169 and b == 254: return True  # link-local
    if a == 172 and 16 <= b <= 31: return True  # RFC1918
    if a == 192 and b == 168: return True  # RFC1918
    if a == 192 and b == 0 and c == 2: return True  # TEST-NET
    if a == 198 and (b == 18 or b == 19): return True
    if a == 198 and b == 51 and c == 100: return True  # TEST-NET
    if a == 203 and b == 0 and c == 113: return True  # TEST-NET
    if a >= 224:      return True   # multicast / reserved
    return False

_IOC_IPV4_ALLOWLIST = {
    # Public DNS providers — frequently cited in articles, never an IOC.
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    # Microsoft / Cloudflare / Google sample IPs
    "20.20.20.20", "13.107.6.152",
}


def _ioc_is_known_safe(value: str, kind: str) -> bool:
    """Return True if the IOC should be dropped from the feed because it's
    known-good infrastructure. Used by extract_indicators() and the
    aggregator to keep `google.com` / `8.8.8.8` etc. out of intel/iocs.csv."""
    if not value:
        return True
    v = value.lower().strip()
    if kind == "domain":
        if v in _IOC_DOMAIN_ALLOWLIST:
            return True
        # Match subdomains of the allowlist (e.g. `cdn.cloudflare.com`)
        for safe in _IOC_DOMAIN_ALLOWLIST:
            if v == safe or v.endswith("." + safe):
                return True
        # Drop bare TLDs / single-label "domains" that slipped through
        if "." not in v:
            return True
        return False
    if kind == "ipv4":
        if v in _IOC_IPV4_ALLOWLIST:
            return True
        if _is_reserved_or_safe_ipv4(v):
            return True
        return False
    return False


# =============================================================================
# Article-mechanic extraction — pulls specific binaries / paths / cmdline
# fragments from the article body so we can emit a bespoke per-article UC
# that hunts THIS attack instead of just keyword-matching to a generic
# template. The output of extract_mechanics() drives _make_bespoke_uc().
# =============================================================================

# Binary names — limit to known-attacker-popular file extensions and reject
# common false positives like file extensions in URLs ("...example.com/foo.exe?dl=1").
_BINARY_RE = re.compile(
    r"(?<![/\w])([A-Za-z0-9_.\-]{2,40}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jse|hta|"
    r"scr|cpl|msi|msp|jar|py|sh|elf))(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# Windows file paths — `C:\...\file.ext` or `%APPDATA%\...`, `\Users\Public\...` etc.
_WIN_PATH_RE = re.compile(
    r"(?<![\w])("
    r"(?:[A-Z]:\\|%[A-Za-z]+%\\|\\Users\\|\\Windows\\|\\ProgramData\\|"
    r"\\AppData\\|\\Temp\\|\\inetpub\\|\\System32\\|\\SysWOW64\\)"
    r"[A-Za-z0-9_.\-\\\\]{2,200}"
    r")",
)
# Unix file paths — start with /, common security-relevant prefixes.
_UNIX_PATH_RE = re.compile(
    r"(?<![\w])("
    r"/(?:tmp|var|etc|usr|opt|home|root|dev|Library|System|private)"
    r"/[A-Za-z0-9_./\-]{2,200}"
    r")",
)
# Registry keys (Run / RunOnce / Services / etc.).
_REGISTRY_RE = re.compile(
    r"(HK[LCU][MR]?\\[A-Za-z0-9_\\\\\.\-]{4,200})",
)
# Persistence container names commonly invoked verbatim.
_PERSISTENCE_KEYWORDS = {
    "scheduled task": "T1053.005",
    "schtasks": "T1053.005",
    "scheduled job": "T1053.005",
    "launchagent": "T1543.001",
    "launchdaemon": "T1543.004",
    "startup folder": "T1547.001",
    "run key": "T1547.001",
    "runonce": "T1547.001",
    "service create": "T1543.003",
    "windows service": "T1543.003",
    "wmi event": "T1546.003",
    "image file execution": "T1546.012",
}
# PowerShell / cmd flag fragments that almost always mean "this was attacker-run".
_CMDLINE_FRAGMENTS = [
    "-EncodedCommand", "-enc ", "FromBase64String", "DownloadString",
    "Invoke-Expression", "IEX(", "Net.WebClient", "-NoProfile -ExecutionPolicy Bypass",
    "-WindowStyle Hidden", "iwr -useb", "certutil -urlcache",
    "bitsadmin /transfer", "rundll32 javascript:", "regsvr32 /s /u /i:",
    "mshta http", "mshta vbscript:", "wmic process call create",
    "powershell -nop -w hidden", "wevtutil cl", "vssadmin delete shadows",
    "wbadmin delete", "bcdedit /set", "fsutil usn deletejournal",
    "/c Reg Add", "Add-MpPreference -ExclusionPath", "Set-MpPreference -DisableRealtime",
]


def extract_mechanics(title: str, body: str) -> dict:
    """Pull article-specific *attack mechanics* (not IOCs).

    What we collect:
      - binaries:   "qakbot.exe", "rclone.exe", "wwlib.dll", ...
      - win_paths:  "C:\\Users\\Public\\setup.exe", "%APPDATA%\\Microsoft\\..."
      - unix_paths: "/tmp/.X11/.malware", "/Library/LaunchAgents/com.evil.plist"
      - registry:   "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\..."
      - persistence: list of (keyword, mitre_tid) pairs found in narrative
      - cmdline_frags: which attacker-style flags / patterns were seen
    """
    text = f"{title}\n{body}"
    text_lower = text.lower()

    # Filter out binary noise (legit OS / utility binaries the article merely
    # mentions — including in CONTEXT). These would ruin signal in a hunt.
    NOISE_BINARIES = {
        # Core Windows
        "explorer.exe", "svchost.exe", "smss.exe", "csrss.exe", "wininit.exe",
        "lsass.exe", "winlogon.exe", "services.exe", "dwm.exe", "spoolsv.exe",
        "fontdrvhost.exe", "lsm.exe", "taskhostw.exe", "runtimebroker.exe",
        # Universal scripting / built-in utilities (almost always used in cmd
        # examples within an article — not a *named attacker tool*)
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe",
        "certutil.exe", "bitsadmin.exe", "msiexec.exe", "regedit.exe",
        "tasklist.exe", "taskkill.exe", "net.exe", "net1.exe", "whoami.exe",
        "systeminfo.exe", "ipconfig.exe", "netsh.exe", "schtasks.exe",
        "sc.exe", "reg.exe", "find.exe", "findstr.exe", "where.exe",
        "ping.exe", "nslookup.exe", "tracert.exe", "ftp.exe", "tftp.exe",
        # Browsers + Office (common contextual mentions)
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
        "brave.exe", "safari.exe", "outlook.exe", "winword.exe", "excel.exe",
        "powerpnt.exe", "onenote.exe", "teams.exe", "ms-teams.exe",
        # Common dev / sysadmin tools
        "code.exe", "cursor.exe", "git.exe", "python.exe", "python3.exe",
        "node.exe", "java.exe", "javaw.exe", "javac.exe", "go.exe",
        # Media / OS chrome
        "wmplayer.exe", "calc.exe", "notepad.exe", "mspaint.exe",
        # Generic short-name files we already filter by length but call out
        "setup.exe", "install.exe", "installer.exe", "update.exe", "uninstall.exe",
    }
    bins = [b.lower() for b in _BINARY_RE.findall(text)]
    bins = [b for b in bins if b not in NOISE_BINARIES and len(b) >= 6
              # Strip out doc-extension strings like "ftp.exe", which are
              # rarely article-specific. Article-specific bins typically have
              # a custom-looking stem (numbers, mixed case, underscores).
              ]
    bins = dedupe(bins)[:25]

    # Generic Windows paths that appear in nearly every Windows-mentioning
    # article. Hunting for "C:\Windows" alone is meaningless — every legit
    # process runs from there. These get filtered out below.
    NOISE_PATH_PREFIXES = (
        "c:\\windows", "c:\\program files", "c:\\users\\", "c:\\programdata",
        "c:\\users\\vagrant", "c:\\users\\analyst", "c:\\users\\sandbox",
        "c:\\users\\malware", "c:\\users\\test", "c:\\users\\admin",
        "c:\\users\\administrator", "c:\\users\\user",
    )
    GENERIC_WIN_PATHS = {
        # Exact-match paths that are almost always non-IOC narrative mentions
        "c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64",
        "c:\\users", "c:\\users\\public", "c:\\programdata",
        "c:\\program files", "c:\\program files (x86)", "c:\\windows\\temp",
    }

    def _path_too_generic(p: str) -> bool:
        pl = p.lower().rstrip("\\")
        if pl in GENERIC_WIN_PATHS:
            return True
        # Researcher / VM artefact paths
        if any(pl.startswith(pref) and len(pl) - len(pref) < 18 for pref in (
            "c:\\users\\vagrant","c:\\users\\analyst","c:\\users\\sandbox",
            "c:\\users\\malware","c:\\users\\test","c:\\users\\admin",
            "c:\\users\\administrator","c:\\users\\user"
        )):
            return True
        # Reject paths that are just a top-level dir with one or zero subdirs
        depth = pl.count("\\")
        if depth <= 1:
            return True
        return False

    raw_win_paths = dedupe(p.replace("\\\\", "\\") for p in _WIN_PATH_RE.findall(text))
    win_paths = [p for p in raw_win_paths if not _path_too_generic(p)][:15]
    unix_paths = dedupe(_UNIX_PATH_RE.findall(text))[:15]
    registry = dedupe(_REGISTRY_RE.findall(text))[:15]

    persistence = []
    for kw, tid in _PERSISTENCE_KEYWORDS.items():
        if kw in text_lower:
            persistence.append({"keyword": kw, "technique": tid})

    cmdline_frags = []
    for f in _CMDLINE_FRAGMENTS:
        if f.lower() in text_lower:
            cmdline_frags.append(f)

    return {
        "binaries": bins,
        "win_paths": win_paths,
        "unix_paths": unix_paths,
        "registry": registry,
        "persistence": persistence,
        "cmdline_frags": cmdline_frags,
    }


# =============================================================================
# LLM-driven bespoke UC generation (opt-in via ANTHROPIC_API_KEY)
# =============================================================================
# Reads the article body with an LLM and emits structured detection content
# specific to the attack described — not a regex-extracted template. Called
# alongside _make_bespoke_uc() (regex). Both run; the LLM output is treated
# as a higher-confidence bespoke UC tier.
#
# Cost note: ~3-6K input tokens + ~1.5K output tokens per article. We
# use Opus 4.7 by default — the article analysis is the place where
# detection quality matters most, so we pay the Opus premium for it
# rather than pinch pennies on Haiku. The cache means an article only
# costs once; re-runs are free until the 24-h re-review pre-pass
# decides the body or peer set has changed.
# Override via USECASEINTEL_LLM_MODEL=<id> if you need to dial down
# (e.g. for a one-off comprehensive corpus run on Haiku).
LLM_UC_CACHE_DIR = Path(__file__).parent / "intel" / ".llm_uc_cache"
LLM_ACTOR_CACHE_DIR = Path(__file__).parent / "intel" / ".llm_actor_uc_cache"
LLM_RELEVANCE_CACHE_DIR = Path(__file__).parent / "intel" / ".llm_relevance_cache"
LLM_UC_MODEL = os.environ.get("USECASEINTEL_LLM_MODEL", "claude-opus-4-7")
# Lighter model for the binary relevance gate — Haiku is plenty for "is this
# article SOC-actionable y/n". Falls back to LLM_UC_MODEL if Haiku is missing.
LLM_RELEVANCE_MODEL = os.environ.get("USECASEINTEL_RELEVANCE_MODEL", "claude-haiku-4-5-20251001")
LLM_UC_MAX_BODY_CHARS = 15000  # cap body length sent to LLM
# Bump this when the relevance prompt or rule set changes — folded into the
# cache key so old decisions don't stick around.
CLASSIFIER_VERSION = "v1"
KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


def _load_kql_knowledge() -> str:
    """Read every knowledge/*.md file and concatenate into a single
    reference block. Loaded once at module import; included verbatim
    in every LLM-driven UC-generation prompt so the model has anchor
    patterns / anti-patterns / table recipes to hand. Cheap (~30 KB)
    and a one-time prompt-cache hit per Claude session.
    Falls back to empty string if the directory is missing — pipeline
    keeps working, just without the knowledge anchors."""
    if not KNOWLEDGE_DIR.exists():
        return ""
    parts = []
    for fname in ("kql_fundamentals.md", "kql_searching_filtering.md",
                  "kql_scalar_functions.md", "kql_combining_data.md",
                  "kql_aggregation_anomaly.md",
                  "kql_patterns.md", "kql_tables.md",
                  "kql_sentinel_tables.md", "kql_translation.md",
                  "kql_antipatterns.md", "kql_examples.md"):
        p = KNOWLEDGE_DIR / fname
        if p.exists():
            try:
                parts.append(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return "\n\n".join(parts)


_KQL_KNOWLEDGE_BLOCK = _load_kql_knowledge()


def _load_datadog_knowledge() -> str:
    """Load knowledge/datadog_fundamentals.md if present — Datadog
    Cloud SIEM log-source / @field.path / query-syntax reference. Same
    pattern as the KQL knowledge loader; degrades gracefully when the
    file is missing."""
    p = KNOWLEDGE_DIR / "datadog_fundamentals.md"
    if p.exists():
        try:
            return p.read_text(encoding="utf-8")
        except Exception:
            return ""
    return ""


_DATADOG_KNOWLEDGE_BLOCK = _load_datadog_knowledge()


def _load_schema_block(filename: str) -> str:
    """Render a data_sources/*.json schema into a compact text block —
    one line per table, columns comma-separated. Injected into the LLM
    prompt so the model never has to guess at column names."""
    schema_path = Path(__file__).parent / "data_sources" / filename
    if not schema_path.exists():
        return ""
    try:
        import json as _j
        raw = _j.loads(schema_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    lines = []
    for t in sorted(raw):
        if t.startswith("_"):
            continue
        cols = raw[t]
        if not isinstance(cols, list):
            continue
        lines.append(f"{t}: {', '.join(cols)}")
    return "\n".join(lines)


_DEFENDER_SCHEMA_BLOCK = _load_schema_block("defender_spec_tables.json")
_SENTINEL_SCHEMA_BLOCK = _load_schema_block("sentinel_spec_tables.json")


# ---- Schema-field validator (canonical Defender table columns) -------------
# Lazy-imported so a missing data_sources/defender_spec_tables.json doesn't
# break the rest of the pipeline.
try:
    from kql_schema_validator import validate_kql as _validate_kql_fields
    from kql_schema_validator import auto_fix_kql as _auto_fix_kql_fields
except Exception:
    _validate_kql_fields = None  # type: ignore[assignment]
    _auto_fix_kql_fields = None  # type: ignore[assignment]

# Sigma rule validator. Optional dependency — pysigma may not be installed.
try:
    from sigma_export import validate_sigma as _validate_sigma_yaml
except Exception:
    _validate_sigma_yaml = None  # type: ignore[assignment]


def _attach_field_issues(uc_dict: dict, kql_key: str = "defender_kql",
                          issues_key: str = "_field_issues",
                          auto_fix: bool = True) -> int:
    """Run the schema validator on uc_dict[kql_key] and attach issues
    to uc_dict[issues_key]. Returns the issue count remaining AFTER
    auto-fix.

    When auto_fix=True (default), the auto-fixer rewrites the query
    in-place for high-confidence wrong-table column references (e.g.
    `AccountName` on `DeviceFileEvents` → `InitiatingProcessAccountName`)
    and difflib-near-miss typos (>=0.8 similarity). The fixup log is
    attached to uc_dict[issues_key + '_autofix'] for audit so we can
    see what the LLM emitted vs what the pipeline shipped.

    Different platforms get different issues_key values so a UC with
    both `defender_kql` + `sentinel_kql` can carry separate audit
    trails (`_field_issues` + `_sentinel_field_issues`)."""
    if _validate_kql_fields is None:
        return 0
    kql = uc_dict.get(kql_key) or ""
    if not kql:
        return 0
    # Pass 1: auto-fix the easy cases. Saves a re-prompt to the LLM and
    # turns "100 broken queries" into "queries that are correct without
    # the analyst noticing they were ever wrong".
    if auto_fix and _auto_fix_kql_fields is not None:
        try:
            fixed_kql, changes = _auto_fix_kql_fields(kql)
        except Exception as e:
            uc_dict[issues_key] = [{"kind": "autofix_error", "message": str(e)[:200]}]
            return 1
        if changes:
            uc_dict[kql_key] = fixed_kql
            uc_dict[issues_key + "_autofix"] = changes
            kql = fixed_kql
    try:
        issues = _validate_kql_fields(kql)
    except Exception as e:
        # Validator must never crash the pipeline.
        uc_dict[issues_key] = [{"kind": "validator_error", "message": str(e)[:200]}]
        return 1
    if issues:
        # Trim to plain dicts in case Issue subclass shows up oddly in JSON.
        uc_dict[issues_key] = [dict(i) for i in issues]
    return len(issues)


def _attach_sigma_issues(uc_dict: dict, sigma_key: str = "sigma_yaml") -> int:
    """Validate uc_dict[sigma_key] via pysigma. Attach issues to
    `_sigma_issues`. Empty / missing sigma_yaml is fine — Sigma is
    optional. Returns the issue count."""
    if _validate_sigma_yaml is None:
        return 0
    body = uc_dict.get(sigma_key) or ""
    if not body.strip():
        return 0
    try:
        issues = _validate_sigma_yaml(body)
    except Exception as e:
        uc_dict["_sigma_issues"] = [f"validator error: {str(e)[:200]}"]
        return 1
    if issues:
        uc_dict["_sigma_issues"] = list(issues)
    return len(issues)


_LLM_UC_PROMPT = """You are a senior detection engineer at a SOC. You will be given a recent threat-intel article. Read it carefully and produce 1-3 high-quality detection use cases that hunt the SPECIFIC attack described — NOT a generic technique template.

You have WebSearch and WebFetch tools available. Before finalising your output, you SHOULD search the web for additional context that can corroborate or enrich the article's claims:
  - Vendor advisories (MSRC, Cisco PSIRT, Fortinet PSIRT) for any CVE mentioned
  - Other vendor write-ups of the same campaign / actor / malware family (Mandiant, CrowdStrike, Microsoft Threat Intel)
  - Public IOC bundles on the campaign (abuse.ch ThreatFox, AlienVault OTX, GitHub IOC-list repos)
  - MITRE ATT&CK group / software pages for any named actor or tool
  - Sigma rules or Splunk Security Content for the same TTPs (so we don't ship a duplicate)

Use what you find to:
  - Validate the IOCs / TTPs (only ship them if at least one second source confirms — drop if only the original article cites them)
  - Add mapped MITRE technique IDs you wouldn't have known from the article alone
  - Fill in actor / campaign / malware-family attribution when the article is vague
  - Note in `rationale` which external sources you cross-checked

Don't search for more than 2-3 things — keep it focused.

IMAGES IN THE ARTICLE — these CAN contain detection-grade content the
text strip misses (command-line screenshots literally showing the
payload string, process-tree diagrams showing the parent→child chain,
phishing-page decoys with the lure URL on screen, C2 panel screenshots,
flowcharts of multi-stage chains). A list of in-article image URLs is
provided below. **WebFetch any image whose filename / position
suggests it's a screenshot or diagram** (don't fetch banner/hero
images, ads, or author headshots). When you do fetch one, extract any
strings/IOCs/parent-child relationships it shows and feed them into
your queries. Cite the image URL in `rationale` if it contributed.


Output STRICT JSON matching this schema (no markdown fences, no prose, just one JSON object):

{
  "ucs": [
    {
      "title": "<concise behavioural title; e.g. 'Mustang Panda DLL side-load via signed Acrobat Reader' — under 100 chars>",
      "description": "<2-3 sentence operational summary; what this hunts and why it's article-specific>",
      "kill_chain": "<one of: recon, weapon, delivery, exploit, install, c2, actions>",
      "tier": "<alerting OR hunting — alerting only when query has named binaries / hashes / threshold / temporal correlation; default hunting>",
      "confidence": "<High, Medium, Low>",
      "fp_rate_estimate": "<low, medium, high, unknown>",
      "required_telemetry": ["<list of data sources e.g. 'Sysmon EID 1', 'Defender DeviceProcessEvents'>"],
      "techniques": [{"id":"T####.###","name":"<technique name>"}],
      "data_models": ["<Splunk CIM dataset names e.g. Endpoint.Processes, Network_Traffic.All_Traffic>"],
      "splunk_spl": "<full Splunk SPL using CIM tstats syntax. Reference SPECIFIC binaries/paths/cmdline strings from the article. Use macros like `summariesonly` and `drop_dm_object_name(<DM>)`.>",
      "defender_kql": "<full Microsoft Defender Advanced Hunting KQL. Use DeviceProcessEvents / DeviceFileEvents / DeviceNetworkEvents / DeviceRegistryEvents / EmailEvents / AADSignInEventsBeta etc. Reference the article's specific strings. Use `Timestamp` (NOT TimeGenerated) — Defender column is Timestamp.>",
      "sentinel_kql": "<full Microsoft Sentinel KQL targeting the SAME detection but on Sentinel's schema. Use SecurityEvent / SigninLogs / AuditLogs / AzureActivity / OfficeActivity / CommonSecurityLog / Syslog / ASIM Im* tables. Use `TimeGenerated` (NOT Timestamp) — Sentinel column is TimeGenerated. If the detection genuinely cannot be expressed on Sentinel telemetry available in this tenant, leave as empty string and explain in `rationale`.>",
      "sigma_yaml": "<OPTIONAL platform-neutral Sigma rule (https://sigmahq.io). Emit ONLY when the detection is single-event-shape (one selection block + condition). Skip Sigma — leave empty string — for: counts/thresholds, time-window correlation, cross-table joins, statistical anomaly, multi-stage chains. Required fields: title, id (UUID), description, references, author, date (YYYY/MM/DD), tags (`attack.t####`), logsource (category + product), detection (selection blocks + condition), level. Use logsource categories: process_creation, file_event, file_access, network_connection, registry_event, dns, image_load, process_access; or product+service for cloud (azure auditlogs / signinlogs / etc.).>",
      "datadog_query": "<Datadog Cloud SIEM logs query string (the bare query, not the full rule wrapper — we wrap it at export time). Use Datadog syntax: `source:<source>` to scope (cloudtrail, windows.security, windows.sysmon, windows.defender, azure.activity_logs, azure.activeDirectory, gcp.audit, kubernetes.audit, okta, linux.auditd, linux.syslog), `@field.path:value` for structured-log attributes, AND/OR/NOT and parentheses, wildcards `*`, CIDR for IPs (`@network.client.ip:81.171.16.0/24`), numeric ranges (`@status:>=400`). Reference the Datadog schema below — only use field paths that actually exist on Datadog's standard log format for the source you're querying. Leave empty string if the detection cannot be expressed on Datadog telemetry (e.g. detection that depends on Defender XDR signals not shipped to Datadog).>",
      "rationale": "<1-2 sentences: which strings/IOCs/behaviours from the article you used and why they're high-fidelity>",
      "corroborated_sources": ["<URLs of any external sources you cross-checked (vendor advisories, other articles, MITRE, abuse.ch). Empty list if you didn't search.>"]
    }
  ]
}

Hard rules:
- Use ACTUAL binaries / paths / hashes / cmdline patterns / domains named in the article. Do not invent or hallucinate.
- If the article describes the attack in narrative only (no specific strings), output {"ucs":[]} — silence beats a generic template.
- Splunk SPL must be CIM-conformant (tstats from datamodel=...).
- Defender KQL must be Advanced Hunting (real table + column names).
- Don't generate the same logic that would already be matched by these existing rules: phishing-link click+exec, LSASS access, PsExec lateral movement, Office spawning scripts, encoded PowerShell. Add ONLY genuinely article-specific detections.
- Maximum 3 UCs per article.

Article title: <<TITLE>>
Article URL: <<URL>>
Article body:
\"\"\"
<<BODY>>
\"\"\"

Pre-extracted IOCs from the article (use these in your queries where appropriate):
<<IOC_SUMMARY>>

In-article image URLs (WebFetch the screenshots/diagrams; skip banner/hero/ads):
<<IMAGE_URLS>>

================================================================
CANONICAL DEFENDER ADVANCED HUNTING SCHEMA
================================================================
Below is the EXACT column list for every Microsoft 365 Defender
Advanced Hunting table you may use. When you write `defender_kql`:

  • Use ONLY columns that appear in this list for the table you are querying.
  • Do NOT invent column names. If the field you want isn't in the
    table, either pick a different table or restructure the query.
  • Defender uses `Timestamp` (NOT TimeGenerated).
  • Common pitfall: `DeviceFileEvents` and `DeviceNetworkEvents` do NOT have
    `AccountName` or `ProcessCommandLine` directly — those are on the
    initiating-process side: `InitiatingProcessAccountName`,
    `InitiatingProcessCommandLine`. Same rule for `FileName` / `ProcessId`.
  • Joins: when both tables share a column name (e.g. `Timestamp`,
    `DeviceId`), the right-hand instance is auto-renamed with a `1`
    suffix (`Timestamp1`, `DeviceId1`).

<<DEFENDER_SCHEMA>>

================================================================
CANONICAL MICROSOFT SENTINEL SCHEMA
================================================================
Below is the column list for the most-used Microsoft Sentinel tables.
When you write `sentinel_kql`:

  • Use ONLY columns that appear in this list for the table you are querying.
  • Sentinel uses `TimeGenerated` (NOT Timestamp). Every where/project
    needs `TimeGenerated`.
  • Schema differs from Defender XDR even when the concept is the same.
    AAD sign-ins live in `SigninLogs` (not AADSignInEventsBeta) and the
    column is `UserPrincipalName` (not AccountUpn). Windows process
    events come via `SecurityEvent | where EventID == 4688` (not
    DeviceProcessEvents) — column is `NewProcessName` (not FileName),
    `CommandLine` (not ProcessCommandLine).
  • Prefer ASIM (`Im*`) tables for cross-vendor portability when
    available: ImProcessCreate, ImNetworkSession, ImAuthentication,
    ImWebSession, ImFileEvent, ImDnsActivity, ImRegistryEvent.
  • If the detection cannot be expressed on Sentinel telemetry (rare —
    e.g. depends on UrlClickEvents which has no clean Sentinel
    equivalent), leave `sentinel_kql` as empty string.

<<SENTINEL_SCHEMA>>

================================================================
KQL DETECTION-ENGINEERING KNOWLEDGE BASE
================================================================
The following reference is the house style for both Defender and
Sentinel KQL queries on this site. Use these patterns / table recipes
/ anti-pattern guidance when shaping the `defender_kql` AND
`sentinel_kql` bodies in your output. Match the style of the
annotated examples — time bounds first, case-insensitive equality
(=~), token-aligned matches (has), process-tree pivots, and explicit
machine-account exclusion. The translation reference shows how to
port a Defender query to Sentinel and vice versa.

<<KQL_KNOWLEDGE>>
================================================================
DATADOG CLOUD SIEM SCHEMA + QUERY SYNTAX
================================================================
Reference for the `datadog_query` field. Use only the field paths
listed below for the source you're scoping with `source:` — Datadog
enforces tag conventions per source and unknown paths return zero
results. CRITICAL: Datadog values are CASE-SENSITIVE (no `=~`
equivalent). When matching binary paths, registry keys, hostnames or
anything that real-world events emit in mixed case, emit BOTH
casings in an OR group, e.g. `@Image:(*\\DTHelper.exe OR
*\\dthelper.exe)`. A single-case match WILL miss legitimate hits.

<<DATADOG_SCHEMA>>
================================================================
"""


def _llm_call_via_oauth(prompt: str, enable_search: bool = True) -> str | None:
    """Call Claude through the user's Claude Code OAuth session via
    claude-agent-sdk. Returns the raw response text or None if the SDK
    isn't installed / the user isn't authenticated.

    When enable_search=True (default), Claude can use the WebSearch tool
    to cross-reference the article against other public sources before
    answering. This is what lets the LLM-emitted UCs reach genuinely
    high fidelity — multiple article sources confirm the IOCs / TTPs."""
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock
    except ImportError:
        return None
    import asyncio
    async def _run():
        chunks = []
        if enable_search:
            # WebSearch lets Claude cross-check the article against vendor
            # advisories, MITRE attributions, public IOC dumps. max_turns=4
            # gives it room to do 1-2 search rounds + the final answer.
            # `model=LLM_UC_MODEL` so the OAuth path honours the same env-
            # var override as the API-key path; otherwise it'd silently
            # fall back to the agent SDK's default.
            options = ClaudeAgentOptions(
                model=LLM_UC_MODEL,
                max_turns=4,
                allowed_tools=["WebSearch", "WebFetch"],
            )
        else:
            options = ClaudeAgentOptions(model=LLM_UC_MODEL, max_turns=1, allowed_tools=[])
        async for msg in query(prompt=prompt, options=options):
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        chunks.append(block.text)
        return "".join(chunks)
    try:
        return asyncio.run(_run())
    except Exception as e:
        safe = str(e).encode("ascii","replace").decode("ascii")[:120]
        print(f"    [!] Claude Code OAuth call failed: {safe}")
        return None


def _llm_call_via_api_key(prompt: str, api_key: str) -> str | None:
    """Call Claude via api.anthropic.com with an x-api-key. Returns raw
    response text or None on error / library missing."""
    try:
        import anthropic
    except ImportError:
        print("    [!] anthropic library not installed — pip install anthropic")
        return None
    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=LLM_UC_MODEL,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in msg.content if hasattr(block, "text"))
    except Exception as e:
        safe = str(e).encode("ascii","replace").decode("ascii")[:120]
        print(f"    [!] Anthropic API call failed: {safe}")
        return None


def _llm_should_process(article: dict, ind: dict) -> bool:
    """Filter — should this article go to the LLM at all?

    Each LLM call costs (token bill or subscription quota) and takes
    30-60s with web search enabled. Skip articles that won't yield
    useful UCs:
      - already-curated briefings (analyst overlay wins)
      - CISA KEV stubs (per-CVE only — IOC-substitution UC handles this)
      - very short bodies (RSS-only, no mechanics)
      - opinion / recap / webinar pieces with no attack mechanics
    """
    # Body length floor — RSS-only stubs are sub-300 chars
    body = article.get("raw_body", "") or ""
    if len(body) < 600:
        return False
    # CISA KEV entries are per-CVE; the asset-exposure template UC is
    # already a perfect match — LLM would just re-emit the same query.
    sources = article.get("sources") or [article.get("source", "")]
    if "CISA KEV" in sources and len(sources) == 1:
        return False
    title_lower = (article.get("title", "") or "").lower()
    body_lower = body.lower()
    # Skip non-attack content
    NON_ATTACK_TITLES = (
        "weekly recap", "this month in security", "in memoriam",
        "5 things to do", "ground zero", "5 places where",
        "what to look for", "webinar:", "webinar -", "podcast",
        "unlocked 403", "threatsday bulletin", "ai-powered defense",
        "making opportunistic", "the agentic soc",
    )
    if any(p in title_lower for p in NON_ATTACK_TITLES):
        return False
    # Want at least one attack-content keyword. Substring-match against
    # title + first 2000 chars of body. Keep this list aligned with the
    # vocabulary modern threat reporting actually uses — see the May 2026
    # TanStack / Mini Shai-Hulud miss for what happens when supply-chain
    # / open-source ecosystem terms are absent here.
    ATTACK_KEYWORDS = (
        # Classic malware vocabulary
        "malware", "malicious", "ransomware", "trojan", "stealer", "steal",
        "backdoor", "exploit", "vulnerab", "campaign", "actor", "apt", "cve-",
        "rce", "0-day", "zero-day", "phishing", "lateral", "dropper",
        "loader", "wiper", "rootkit", "implant", "botnet", "intrusion",
        "hacked", "hack", "compromise", "breach",
        # Supply-chain / open-source ecosystem (the gap that hid Mini Shai-Hulud)
        "supply chain", "supply-chain", "npm", "pypi", "rubygems", "packagist",
        "postinstall", "post-install", "package compromise", "malicious package",
        "trojanized", "trojanised", "typosquat", "typo-squat", "brand squat",
        "brandsquat", "brand-squat", "dependency confusion", "worm",
        "self-spreading", "self-replicating",
        # CI/CD + cloud identity attack surface
        "github actions", "ci/cd", "ci credentials", "ci secrets",
        "oidc", "secrets exfil", "token theft", "credential theft",
        "pull_request_target", "pwn request", "cache poisoning",
        # Named-incident shorthand we know about (regex-cheap & high-precision)
        "shai-hulud", "shai hulud",
    )
    if not any(kw in title_lower or kw in body_lower[:2000] for kw in ATTACK_KEYWORDS):
        return False
    return True


def _llm_generate_ucs(article: dict, ind: dict):
    """Call Claude with the article body and parse a list of UseCase objects
    from the JSON response. Three auth paths, in priority order:
      1. USECASEINTEL_USE_CLAUDE_OAUTH=1 — claude-agent-sdk + user's
         Claude Code session (Pro / Max subscription)
      2. ANTHROPIC_API_KEY=... — direct API key (pay-per-token billing)
      3. neither set — skip cleanly, pipeline runs without LLM UCs
    Cached on disk by article URL hash so repeat runs cost nothing.
    Filtered to attack-content articles only — see _llm_should_process()."""
    use_oauth = os.environ.get("USECASEINTEL_USE_CLAUDE_OAUTH", "").lower() in ("1", "true", "yes")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    url = article.get("link", "")
    if not url:
        return []
    # Cache is consulted regardless of auth-env state — cached responses are
    # free to read and represent past analyst-grade work that should keep
    # flowing into the site even when the operator runs without the LLM
    # creds set (e.g. a quick UI-only rebuild). Only NEW LLM calls require
    # auth; the env-var gate moved below the cache lookup.
    LLM_UC_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_key = hashlib.sha1(url.encode("utf-8", "replace")).hexdigest()
    cache_path = LLM_UC_CACHE_DIR / f"{cache_key[:2]}/{cache_key}.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists():
        try:
            data = __import__("json").loads(cache_path.read_text(encoding="utf-8"))
            return [_uc_from_llm_dict(d) for d in data.get("ucs", []) if d]
        except Exception:
            pass
    # Cache miss — only proceed to make a new LLM call if auth is configured.
    if not use_oauth and not api_key:
        return []
    # USECASEINTEL_LLM_SKIP_FILTER=1 forces the LLM to process every
    # article regardless of attack-content heuristics. Useful for a
    # comprehensive corpus review; default-on filter saves tokens on
    # opinion / recap / webinar pieces.
    skip_filter = os.environ.get("USECASEINTEL_LLM_SKIP_FILTER", "").lower() in ("1", "true", "yes")
    if not skip_filter and not _llm_should_process(article, ind):
        return []
    body = (article.get("raw_body") or "")[:LLM_UC_MAX_BODY_CHARS]
    if len(body) < 200:
        return []  # not enough content for the LLM to ground on
    ioc_summary = []
    for k, label in [("cves","CVEs"),("ips","IPs"),("domains","Domains"),
                     ("sha256","SHA256"),("sha1","SHA1"),("md5","MD5")]:
        if ind.get(k):
            ioc_summary.append(f"  {label}: {', '.join(ind[k][:8])}")
    # In-article images — the LLM can WebFetch any that look like screenshots
    # or diagrams. Capped at 5 by the extractor; we list them numbered so
    # the model can reference them in `rationale`.
    image_urls = article.get("image_urls") or []
    if image_urls:
        image_block = "\n".join(f"  [{i+1}] {u}" for i, u in enumerate(image_urls))
    else:
        image_block = "  (none extracted)"
    # Manual placeholder substitution — the prompt body contains literal
    # JSON `{...}` braces which would confuse str.format(), causing every
    # call to fail with a KeyError before ever reaching the LLM.
    prompt = (_LLM_UC_PROMPT
              .replace("<<TITLE>>",       article.get("title", "")[:200])
              .replace("<<URL>>",         url[:200])
              .replace("<<BODY>>",        body)
              .replace("<<IOC_SUMMARY>>", "\n".join(ioc_summary) or "  (none)")
              .replace("<<IMAGE_URLS>>",  image_block)
              .replace("<<DEFENDER_SCHEMA>>", _DEFENDER_SCHEMA_BLOCK)
              .replace("<<SENTINEL_SCHEMA>>", _SENTINEL_SCHEMA_BLOCK)
              .replace("<<KQL_KNOWLEDGE>>", _KQL_KNOWLEDGE_BLOCK)
              .replace("<<DATADOG_SCHEMA>>", _DATADOG_KNOWLEDGE_BLOCK))
    raw = None
    if use_oauth:
        raw = _llm_call_via_oauth(prompt)
    if raw is None and api_key:
        raw = _llm_call_via_api_key(prompt, api_key)
    if raw is None:
        return []
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```\s*$", "", raw)
    # The Agent SDK sometimes wraps the JSON in chatty prose. Try to
    # extract the first balanced { ... } block if a direct parse fails.
    json_lib = __import__("json")
    try:
        data = json_lib.loads(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                data = json_lib.loads(m.group(0))
            except Exception as e:
                print(f"    [!] LLM output JSON-parse failed: {str(e)[:80]}")
                return []
        else:
            print(f"    [!] LLM output had no JSON block: {raw[:80]!r}")
            return []
    # Schema-field validation — flag any column the LLM invented or used on
    # the wrong table for either platform. Issues are attached per-platform
    # to each UC in the cache for later auditing via validate_kql_knowledge.py.
    total_issues = 0
    total_sigma_issues = 0
    for uc in data.get("ucs") or []:
        if isinstance(uc, dict):
            total_issues += _attach_field_issues(uc, "defender_kql")
            total_issues += _attach_field_issues(uc, "sentinel_kql",
                                                  issues_key="_sentinel_field_issues")
            total_sigma_issues += _attach_sigma_issues(uc, "sigma_yaml")
    if total_issues:
        print(f"    [!] {total_issues} field-schema issue(s) flagged across {len(data.get('ucs') or [])} UC(s)")
    if total_sigma_issues:
        print(f"    [!] {total_sigma_issues} Sigma rule issue(s) across {len(data.get('ucs') or [])} UC(s)")
    # Stamp the cache with the inputs we used so the 24h re-review pass
    # can detect when an article's body has been edited, a new image has
    # been added, or when a similar article has appeared elsewhere.
    body_for_hash = body + "\n#IMAGES:" + "\n".join(image_urls)
    data["_body_hash"]     = hashlib.sha256(body_for_hash.encode("utf-8", "replace")).hexdigest()
    data["_similar_count"] = int(article.get("_similar_count", 0))
    data["_image_count"]   = len(image_urls)
    data["_analyzed_at"]   = dt.datetime.now(dt.timezone.utc).isoformat()
    cache_path.write_text(json_lib.dumps(data, indent=2), encoding="utf-8")
    return [_uc_from_llm_dict(d) for d in (data.get("ucs") or []) if d]


def _recent_window_revisit(articles, hours: int = 24) -> int:
    """Pre-pass: for every article published within the last `hours`
    hours, check whether its cached LLM analysis has gone stale and
    invalidate it if so. Two staleness triggers:

      1. **Body changed.** The article was edited after we last analysed
         it (publishers routinely add IOCs / vendor links / corrections).
         We compare SHA256 of the body we'd send the LLM today against
         the `_body_hash` recorded when the cache was written.

      2. **A similar article appeared elsewhere.** Cross-source dedupe
         keeps only one card, but if a SECOND vendor publishes a
         write-up of the same campaign after our first analysis, the
         second write-up frequently brings new mechanics. We compare
         current similar-title count (Jaccard ≥ 0.55) against the
         `_similar_count` recorded at analysis time.

    Each invalidated cache file is renamed `*.invalidated-<ts>` rather
    than deleted, so we can roll back if a regression sneaks in. Returns
    the number of cache files invalidated."""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    # Pre-tokenize titles once for the similarity walk.
    def _tok(t):
        return {w.lower() for w in re.findall(r"[A-Za-z0-9]+", t or "") if len(w) > 2}
    title_tokens_by_url = {}
    for a in articles:
        url = a.get("link") or ""
        if url:
            title_tokens_by_url[url] = _tok(a.get("title", ""))

    # Annotate each article with its current similar-article count, so
    # _llm_generate_ucs can persist that value when it caches.
    for a in articles:
        my = title_tokens_by_url.get(a.get("link") or "")
        if not my:
            a["_similar_count"] = 0
            continue
        count = 0
        for other_url, other_tok in title_tokens_by_url.items():
            if other_url == a.get("link"):
                continue
            if not other_tok:
                continue
            inter = len(my & other_tok)
            union = len(my | other_tok)
            if union and (inter / union) >= 0.55:
                count += 1
        a["_similar_count"] = count

    invalidated = 0
    for a in articles:
        pub = a.get("published_dt")
        if not isinstance(pub, dt.datetime):
            continue
        # Some feeds emit naive datetimes; coerce to UTC for the compare.
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=dt.timezone.utc)
        if pub < cutoff:
            continue
        url = a.get("link") or ""
        if not url:
            continue
        cache_key = hashlib.sha1(url.encode("utf-8", "replace")).hexdigest()
        cache_path = LLM_UC_CACHE_DIR / f"{cache_key[:2]}/{cache_key}.json"
        if not cache_path.exists():
            continue
        try:
            data = __import__("json").loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        body = (a.get("raw_body") or "")[:LLM_UC_MAX_BODY_CHARS]
        image_urls = a.get("image_urls") or []
        body_for_hash = body + "\n#IMAGES:" + "\n".join(image_urls)
        cur_hash = hashlib.sha256(body_for_hash.encode("utf-8", "replace")).hexdigest()
        body_changed = bool(data.get("_body_hash")) and data["_body_hash"] != cur_hash
        cached_similar = int(data.get("_similar_count", 0))
        cur_similar = int(a.get("_similar_count", 0))
        similar_grew = cur_similar > cached_similar
        cached_imgs = int(data.get("_image_count", 0))
        cur_imgs = len(image_urls)
        images_grew = cur_imgs > cached_imgs

        if not (body_changed or similar_grew or images_grew):
            continue
        ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        target = cache_path.with_suffix(cache_path.suffix + f".invalidated-{ts}-revisit")
        try:
            cache_path.rename(target)
            invalidated += 1
            reasons = []
            if body_changed: reasons.append("body changed")
            if images_grew:  reasons.append(f"images {cached_imgs}->{cur_imgs}")
            if similar_grew: reasons.append(f"similar {cached_similar}->{cur_similar}")
            title = (a.get("title") or "")[:60]
            print(f"    [revisit] {title} ({', '.join(reasons)})")
        except Exception as _e:
            # Disk weirdness shouldn't block the pipeline.
            print(f"    [!] revisit rename failed for {url[:60]}: {_e}")

    if invalidated:
        print(f"[*] 24h re-review: invalidated {invalidated} cache file(s) for re-analysis")
    return invalidated


# Prompt for the per-actor LLM bespoke detections. Different shape from
# the article prompt because the analyst signal is a TTP profile rather
# than a narrative — emphasise specificity to that actor's known
# tradecraft over generic technique templates.
_LLM_ACTOR_PROMPT = """You are a senior detection engineer at a SOC. You will be given a structured profile of a tracked threat actor (APT or e-crime crew) and you must produce 1-2 high-fidelity detection use cases that would catch THIS actor's specific tradecraft.

Quality bar:
  - Each UC must hunt SPECIFIC TTPs the actor is known for, NOT a generic technique template. Pull on the actor's name, attribution, motivation, and known technique combination (look for chains like initial-access → execution → lateral-movement that this actor characteristically uses).
  - Defender KQL: use real Advanced Hunting tables (DeviceProcessEvents, EmailEvents, UrlClickEvents, AADSignInEventsBeta, DeviceNetworkEvents, IdentityLogonEvents, DeviceFileEvents, etc.).
  - Splunk SPL: CIM-conformant. Use `tstats` against accelerated data models (Endpoint, Network_Traffic, Authentication, Email, Web).
  - Cite the actor's real CrowdStrike / Microsoft / Mandiant cluster names if applicable (e.g. APT29 = Cozy Bear / Midnight Blizzard).
  - If the actor's technique list is sparse or unfocused, prefer ONE strong UC over two weak ones.

Reply with JSON only, no commentary, this exact shape:
```json
{
  "ucs": [
    {
      "title": "<short, actor-specific title — e.g. 'APT29 token theft via OAuth illicit-grant flow'>",
      "description": "<1-2 sentences on what this hunts and why it's tied to THIS actor>",
      "kill_chain": "<one of: recon, weapon, delivery, exploit, install, c2, actions>",
      "techniques": [{"id":"T####", "name":"<official MITRE name>"}, ...],
      "data_models": ["Endpoint.Processes", ...],
      "splunk_spl": "<full SPL query>",
      "defender_kql": "<full Microsoft Defender Advanced Hunting KQL — uses `Timestamp`>",
      "sentinel_kql": "<full Microsoft Sentinel KQL targeting the same detection — uses `TimeGenerated`. Empty string if not expressible on Sentinel telemetry.>",
      "sigma_yaml": "<OPTIONAL platform-neutral Sigma rule. Emit only for single-event-shape detections; empty string otherwise. See article-prompt guidance for the field schema.>",
      "datadog_query": "<Datadog Cloud SIEM logs query string targeting the same detection. Use `source:<source>` + `@field.path:value` syntax — see Datadog schema reference at the end of this prompt. Empty string if not expressible on Datadog telemetry.>",
      "confidence": "high | medium | low",
      "tier": "alerting | hunting",
      "fp_rate_estimate": "low | medium | high",
      "required_telemetry": ["<table or data model>", ...],
      "rationale": "<why this catches this actor specifically vs random APTs>"
    }
  ]
}
```

ACTOR PROFILE
=============
Name: <<NAME>>
Aliases: <<ALIASES>>
Country: <<COUNTRY>>
Motivation: <<MOTIVATION>>
MITRE ID: <<MITRE_ID>>

MITRE description:
<<DESCRIPTION>>

Top-known MITRE techniques (technique-id list, sample of full set):
<<TECHNIQUES>>

================================================================
CANONICAL DEFENDER ADVANCED HUNTING SCHEMA
================================================================
Below is the EXACT column list for every Microsoft 365 Defender
Advanced Hunting table you may use. When you write `defender_kql`:

  • Use ONLY columns that appear in this list for the table you are querying.
  • Do NOT invent column names. If the field you want isn't in the
    table, either pick a different table or restructure the query.
  • Defender uses `Timestamp` (NOT TimeGenerated).
  • Common pitfall: `DeviceFileEvents` and `DeviceNetworkEvents` do NOT have
    `AccountName` or `ProcessCommandLine` directly — those are on the
    initiating-process side: `InitiatingProcessAccountName`,
    `InitiatingProcessCommandLine`. Same rule for `FileName` / `ProcessId`.
  • Joins: when both tables share a column name (e.g. `Timestamp`,
    `DeviceId`), the right-hand instance is auto-renamed with a `1`
    suffix (`Timestamp1`, `DeviceId1`).

<<DEFENDER_SCHEMA>>

================================================================
CANONICAL MICROSOFT SENTINEL SCHEMA
================================================================
Below is the column list for the most-used Microsoft Sentinel tables.
When you write `sentinel_kql`:

  • Use ONLY columns that appear in this list for the table you are querying.
  • Sentinel uses `TimeGenerated` (NOT Timestamp). Every where/project
    needs `TimeGenerated`.
  • Schema differs from Defender XDR even when the concept is the same.
    AAD sign-ins live in `SigninLogs` (not AADSignInEventsBeta) and the
    column is `UserPrincipalName` (not AccountUpn). Windows process
    events come via `SecurityEvent | where EventID == 4688` (not
    DeviceProcessEvents) — column is `NewProcessName` (not FileName),
    `CommandLine` (not ProcessCommandLine).
  • Prefer ASIM (`Im*`) tables for cross-vendor portability when
    available: ImProcessCreate, ImNetworkSession, ImAuthentication,
    ImWebSession, ImFileEvent, ImDnsActivity, ImRegistryEvent.
  • If the detection cannot be expressed on Sentinel telemetry (rare —
    e.g. depends on UrlClickEvents which has no clean Sentinel
    equivalent), leave `sentinel_kql` as empty string.

<<SENTINEL_SCHEMA>>

================================================================
KQL DETECTION-ENGINEERING KNOWLEDGE BASE
================================================================
The following reference is the house style for both Defender and
Sentinel KQL queries on this site. Use these patterns / table recipes
/ anti-pattern guidance when shaping the `defender_kql` AND
`sentinel_kql` bodies in your output. Match the style of the
annotated examples — time bounds first, case-insensitive equality
(=~), token-aligned matches (has), process-tree pivots, and explicit
machine-account exclusion. The translation reference shows how to
port a Defender query to Sentinel and vice versa.

<<KQL_KNOWLEDGE>>
================================================================
DATADOG CLOUD SIEM SCHEMA + QUERY SYNTAX
================================================================
Reference for the `datadog_query` field. Use only the field paths
listed below for the source you're scoping with `source:` — Datadog
enforces tag conventions per source and unknown paths return zero
results. CRITICAL: Datadog values are CASE-SENSITIVE (no `=~`
equivalent). When matching binary paths, registry keys, hostnames or
anything that real-world events emit in mixed case, emit BOTH
casings in an OR group, e.g. `@Image:(*\\DTHelper.exe OR
*\\dthelper.exe)`. A single-case match WILL miss legitimate hits.

<<DATADOG_SCHEMA>>
================================================================
"""


def _llm_generate_actor_ucs(actor: dict):
    """Generate 1-2 LLM-bespoke detection UCs for a tracked threat
    actor, given their MITRE profile. Cached on disk per actor name +
    technique-set hash so re-runs are free, and so a future technique
    list change invalidates the cache cleanly. Returns [] if no auth
    is configured (cache miss + skip).
    Output shape mirrors _llm_generate_ucs but each dict is annotated
    with `is_llm: True, source_kind: 'actor-bespoke'` so the drawer
    UI can label them differently from article-bound LLM UCs."""
    use_oauth = os.environ.get("USECASEINTEL_USE_CLAUDE_OAUTH", "").lower() in ("1", "true", "yes")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    name = (actor.get("name") or "").strip()
    techs = sorted(actor.get("techs") or actor.get("techniques") or [])
    if not name or len(techs) < 3:
        return []   # too sparse for a meaningful actor-driven UC
    LLM_ACTOR_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    sig = f"{name}|{','.join(techs)}"
    cache_key = hashlib.sha1(sig.encode("utf-8", "replace")).hexdigest()
    cache_path = LLM_ACTOR_CACHE_DIR / f"{cache_key[:2]}/{cache_key}.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists():
        try:
            data = __import__("json").loads(cache_path.read_text(encoding="utf-8"))
            return data.get("ucs") or []
        except Exception:
            pass
    # Cache miss — only proceed if auth is configured.
    if not use_oauth and not api_key:
        return []
    aliases = (actor.get("aliases") or [])[:8]
    description = (actor.get("mitre_description") or actor.get("description") or "")[:600]
    prompt = (_LLM_ACTOR_PROMPT
              .replace("<<NAME>>", name)
              .replace("<<ALIASES>>", ", ".join(aliases) or "(none)")
              .replace("<<COUNTRY>>", actor.get("country", "??"))
              .replace("<<MOTIVATION>>", actor.get("motivation", "unknown"))
              .replace("<<MITRE_ID>>", actor.get("mitre_id", ""))
              .replace("<<DESCRIPTION>>", description or "(no description in MITRE bundle)")
              .replace("<<TECHNIQUES>>", ", ".join(techs[:60]))
              .replace("<<DEFENDER_SCHEMA>>", _DEFENDER_SCHEMA_BLOCK)
              .replace("<<SENTINEL_SCHEMA>>", _SENTINEL_SCHEMA_BLOCK)
              .replace("<<KQL_KNOWLEDGE>>", _KQL_KNOWLEDGE_BLOCK)
              .replace("<<DATADOG_SCHEMA>>", _DATADOG_KNOWLEDGE_BLOCK))
    raw = None
    try:
        if use_oauth:
            raw = _llm_call_via_oauth(prompt, enable_search=False)
        elif api_key:
            raw = _llm_call_via_api_key(prompt, api_key)
    except Exception as _e:
        print(f"    [!] actor-LLM call failed for {name}: {_e}")
        return []
    if not raw:
        return []
    # Parse — same fence-stripping as _llm_generate_ucs
    json_lib = __import__("json")
    raw = raw.strip()
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
    try:
        data = json_lib.loads(raw)
    except Exception:
        # Try pulling a JSON block out of mixed text
        import re as _re
        m = _re.search(r"\{[\s\S]*\}", raw)
        if m:
            try:
                data = json_lib.loads(m.group(0))
            except Exception:
                print(f"    [!] actor-LLM JSON unparseable for {name}")
                return []
        else:
            return []
    out_ucs = []
    for d in (data.get("ucs") or []):
        if not isinstance(d, dict): continue
        title = (d.get("title") or "").strip()
        if not title: continue
        title = _re.sub(r"^(\[LLM\]\s*)+", "", title) if (_re := __import__("re")) else title
        out_ucs.append({
            "title": f"[LLM] {title[:140]}",
            "description": (d.get("description") or "")[:600],
            "is_llm": True,
            "source_kind": "actor-bespoke",
            "phase": d.get("kill_chain", "actions"),
            "conf": d.get("confidence", "Medium"),
            "techs": [t.get("id") if isinstance(t, dict) else t for t in (d.get("techniques") or [])][:8],
            "art_id": "",
            "art_title": "",
            "is_mitre_match": False,
            "splunk": d.get("splunk_spl") or "",
            "kql": d.get("defender_kql") or "",
            "sentinel_kql": d.get("sentinel_kql") or "",
            "sigma_yaml": d.get("sigma_yaml") or "",
            "rationale": (d.get("rationale") or "")[:400],
        })
    # Schema-field + Sigma validation per platform. Actor cache stores
    # `kql` (Defender), `sentinel_kql`, `sigma_yaml` separately.
    total_issues = 0
    total_sigma_issues = 0
    for uc in out_ucs:
        total_issues += _attach_field_issues(uc, "kql")
        total_issues += _attach_field_issues(uc, "sentinel_kql",
                                              issues_key="_sentinel_field_issues")
        total_sigma_issues += _attach_sigma_issues(uc, "sigma_yaml")
    if total_issues:
        print(f"    [!] {total_issues} field-schema issue(s) flagged across {len(out_ucs)} actor UC(s)")
    if total_sigma_issues:
        print(f"    [!] {total_sigma_issues} Sigma rule issue(s) across {len(out_ucs)} actor UC(s)")
    cache_path.write_text(json_lib.dumps({"name": name, "ucs": out_ucs}, indent=2), encoding="utf-8")
    return out_ucs


def _uc_from_llm_dict(d: dict):
    """Validate + coerce an LLM-emitted UC dict into a UseCase object."""
    if not isinstance(d, dict): return None
    title = (d.get("title") or "").strip()
    spl = d.get("splunk_spl") or ""
    kql = d.get("defender_kql") or ""
    if not title or not (spl or kql):
        return None
    techs = []
    for t in (d.get("techniques") or []):
        tid = (t or {}).get("id") if isinstance(t, dict) else t
        tname = (t or {}).get("name", "") if isinstance(t, dict) else ""
        if tid and re.match(r"^T\d{4}(\.\d{3})?$", str(tid)):
            techs.append((tid, tname or ""))
    tier = (d.get("tier") or "hunting").lower()
    if tier not in ("alerting", "hunting"):
        tier = "hunting"
    fp_rate = (d.get("fp_rate_estimate") or "unknown").lower()
    if fp_rate not in ("low", "medium", "high", "unknown"):
        fp_rate = "unknown"
    req_telem = d.get("required_telemetry") or []
    if not isinstance(req_telem, list):
        req_telem = [str(req_telem)]
    desc_parts = [(d.get("description") or "").strip()]
    if d.get("rationale"):
        desc_parts.append("\n\nRationale: " + (d.get("rationale") or "").strip())
    cs = d.get("corroborated_sources") or []
    if isinstance(cs, list) and cs:
        desc_parts.append("\n\nCross-checked against:")
        for u in cs[:6]:
            desc_parts.append(f"\n  • {u}")
    # If the LLM emitted a title that already begins with "[LLM]" we
    # don't want to compound to "[LLM] [LLM] foo" — strip any leading
    # repetitions before adding our canonical single prefix.
    title = re.sub(r"^(\[LLM\]\s*)+", "", title).strip()
    return UseCase(
        title=f"[LLM] {title[:140]}",
        description="".join(desc_parts),
        kill_chain=(d.get("kill_chain") or "actions"),
        techniques=techs,
        data_models=list(d.get("data_models") or []),
        splunk_spl=spl,
        defender_kql=kql,
        sentinel_kql=(d.get("sentinel_kql") or ""),
        sigma_yaml=(d.get("sigma_yaml") or ""),
        datadog_query=(d.get("datadog_query") or ""),
        confidence=(d.get("confidence") or "Medium"),
        tier=tier,
        fp_rate_estimate=fp_rate,
        required_telemetry=[str(t) for t in req_telem][:8],
    )


def _make_bespoke_uc(article_title: str, mechanics: dict, ind: dict):
    """Assemble a *per-article* UseCase from the extracted mechanics.

    Returns None if there's not enough article-specific signal to build a
    meaningful detection — better silence than a query that fires on every
    `chrome.exe` execution. Threshold: at least one of (binary, win_path,
    unix_path, registry, cmdline_frag) must be present.
    """
    bins = mechanics.get("binaries") or []
    wpaths = mechanics.get("win_paths") or []
    upaths = mechanics.get("unix_paths") or []
    regs = mechanics.get("registry") or []
    cmdfrags = mechanics.get("cmdline_frags") or []
    persistence = mechanics.get("persistence") or []

    # Require a real article-specific anchor — otherwise we'd be emitting a
    # generic query that hunts on, e.g., the standard Run key alone, which is
    # neither novel nor article-specific.
    if not any([bins, wpaths, upaths, regs, cmdfrags]):
        return None

    safe_title = article_title[:80].strip()

    # Build SPL — a process / filesystem hunt scoped to the article's mechanics.
    spl_parts = []
    spl_parts.append(f'``` Article-specific bespoke detection — {safe_title} ```')

    proc_clauses = []
    if bins:
        bin_list = ",".join(f'"{b}"' for b in bins[:15])
        proc_clauses.append(f"Processes.process_name IN ({bin_list})")
    if cmdfrags:
        for f in cmdfrags[:6]:
            proc_clauses.append(f'Processes.process="*{f}*"')
    if wpaths:
        for p in wpaths[:5]:
            esc = p.replace('"', '\\"')
            proc_clauses.append(f'Processes.process_path="*{esc}*"')

    if proc_clauses:
        clauses = " OR ".join(proc_clauses)
        spl_parts.append(
            "| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime\n"
            "    from datamodel=Endpoint.Processes\n"
            f"    where ({clauses})\n"
            "    by Processes.dest, Processes.user, Processes.process_name,\n"
            "       Processes.process, Processes.parent_process_name, Processes.process_path\n"
            "| `drop_dm_object_name(Processes)`\n"
            "| `security_content_ctime(firstTime)`"
        )

    fs_clauses = []
    if wpaths or upaths:
        for p in (wpaths + upaths)[:8]:
            esc = p.replace('"', '\\"')
            fs_clauses.append(f'Filesystem.file_path="*{esc}*"')
    if bins:
        # Also surface filesystem-create events for the named binaries
        bin_filenames = ",".join(f'"{b}"' for b in bins[:15])
        fs_clauses.append(f"Filesystem.file_name IN ({bin_filenames})")
    if fs_clauses:
        clauses = " OR ".join(fs_clauses)
        if proc_clauses:
            spl_parts.append("| append [")
        spl_parts.append(
            "| tstats `summariesonly` count\n"
            "    from datamodel=Endpoint.Filesystem\n"
            f"    where Filesystem.action IN (\"created\",\"modified\")\n"
            f"      AND ({clauses})\n"
            "    by Filesystem.dest, Filesystem.user, Filesystem.process_name,\n"
            "       Filesystem.file_path, Filesystem.file_name\n"
            "| `drop_dm_object_name(Filesystem)`"
        )
        if proc_clauses:
            spl_parts.append("]")

    if regs:
        reg_clauses = []
        for r in regs[:6]:
            esc = r.replace('"', '\\"').replace("\\", "\\\\")
            reg_clauses.append(f'Registry.registry_path="*{esc}*"')
        clauses = " OR ".join(reg_clauses)
        spl_parts.append(
            "| append [\n"
            "  | tstats `summariesonly` count\n"
            "      from datamodel=Endpoint.Registry\n"
            f"      where Registry.action IN (\"created\",\"modified\")\n"
            f"        AND ({clauses})\n"
            "      by Registry.dest, Registry.process_name, Registry.registry_path,\n"
            "         Registry.registry_value_name, Registry.registry_value_data\n"
            "  | `drop_dm_object_name(Registry)`\n"
            "]"
        )

    spl = "\n".join(spl_parts)

    # Build KQL — same shape, Defender XDR tables.
    kql_lines = [
        f"// Article-specific bespoke detection — {safe_title}",
        f"// Hunts the actual binaries / paths / commandline fragments named",
        f"// in the article instead of a generic technique-class template.",
    ]
    proc_filters = []
    if bins:
        proc_filters.append(
            "FileName in~ (" + ", ".join(f'"{b}"' for b in bins[:15]) + ")")
    if cmdfrags:
        cf = ", ".join(f'"{f}"' for f in cmdfrags[:6])
        proc_filters.append(f"ProcessCommandLine has_any ({cf})")
    if wpaths:
        # KQL has_any expects no leading/trailing wildcards
        wp = ", ".join(f'"{p}"' for p in wpaths[:5])
        proc_filters.append(f"FolderPath has_any ({wp})")

    if proc_filters:
        kql_lines.append("DeviceProcessEvents")
        kql_lines.append("| where Timestamp > ago(30d)")
        kql_lines.append("| where (" + " or ".join(proc_filters) + ")")
        kql_lines.append("| project Timestamp, DeviceName, AccountName, FileName,")
        kql_lines.append("          FolderPath, ProcessCommandLine,")
        kql_lines.append("          InitiatingProcessFileName, InitiatingProcessCommandLine")
        kql_lines.append("| order by Timestamp desc")

    fs_filters = []
    if wpaths or upaths:
        all_paths = (wpaths + upaths)[:8]
        if all_paths:
            fp = ", ".join(f'"{p}"' for p in all_paths)
            fs_filters.append(f"FolderPath has_any ({fp})")
    if bins:
        bf = ", ".join(f'"{b}"' for b in bins[:15])
        fs_filters.append(f"FileName in~ ({bf})")
    if fs_filters:
        kql_lines.append("\n// File-creation events for the named binaries / paths")
        kql_lines.append("DeviceFileEvents")
        kql_lines.append("| where Timestamp > ago(30d)")
        kql_lines.append("| where ActionType in (\"FileCreated\",\"FileModified\")")
        kql_lines.append("| where (" + " or ".join(fs_filters) + ")")
        kql_lines.append("| project Timestamp, DeviceName, AccountName, FolderPath,")
        kql_lines.append("          FileName, ActionType, InitiatingProcessFileName,")
        kql_lines.append("          InitiatingProcessCommandLine")
        kql_lines.append("| order by Timestamp desc")

    if regs:
        rkql = ", ".join(f'"{r}"' for r in regs[:6])
        kql_lines.append("\n// Registry persistence locations named in the article")
        kql_lines.append("DeviceRegistryEvents")
        kql_lines.append("| where Timestamp > ago(30d)")
        kql_lines.append("| where ActionType in (\"RegistryValueSet\",\"RegistryKeyCreated\")")
        kql_lines.append(f"| where RegistryKey has_any ({rkql})")
        kql_lines.append("| project Timestamp, DeviceName, AccountName, RegistryKey,")
        kql_lines.append("          RegistryValueName, RegistryValueData,")
        kql_lines.append("          InitiatingProcessFileName, InitiatingProcessCommandLine")
        kql_lines.append("| order by Timestamp desc")

    kql = "\n".join(kql_lines)

    # Pick a kill-chain phase and a representative technique.
    if cmdfrags or bins:
        ph = "exploit"
    elif persistence:
        ph = "install"
    elif regs:
        ph = "install"
    elif wpaths or upaths:
        ph = "install"
    else:
        ph = "actions"

    techs = []
    if cmdfrags:
        techs.append(("T1059.001", "PowerShell"))
        techs.append(("T1027", "Obfuscated Files or Information"))
    if persistence:
        for p in persistence[:3]:
            techs.append((p["technique"], "Persistence (article-specific)"))
    if not techs:
        techs.append(("T1204.002", "User Execution: Malicious File"))

    # Tier: bespoke article UCs are HUNTING by default — they list rows
    # matching strings extracted from the article body. They lack
    # environment baselining (legit binary allowlist) and false-positive
    # suppression. An analyst should run them as hunts, then promote to
    # alerting after tuning + adding suppression.
    return UseCase(
        title=f"Article-specific behavioural hunt — {safe_title}",
        description=(
            "Auto-generated hunt targeting the specific binaries, paths, "
            "registry locations and command-line fragments named in this "
            "article. Hunting tier — needs analyst review and environment "
            "tuning before promotion to alerting."
        ),
        kill_chain=ph,
        techniques=techs,
        data_models=["Endpoint.Processes", "Endpoint.Filesystem", "Endpoint.Registry"],
        splunk_spl=spl,
        defender_kql=kql,
        confidence="High",
        tier="hunting",
    )


# =============================================================================
# Cyber Kill Chain (Lockheed Martin) phases
# =============================================================================

KILL_CHAIN_PHASES = [
    ("recon", "Reconnaissance", "Attacker researches the target — OSINT, scanning, enumeration."),
    ("weapon", "Weaponization", "Coupling exploit code with deliverable payload (e.g. weaponized PDF/Office doc, trojanized installer)."),
    ("delivery", "Delivery", "Transmitting the weapon (phishing email, USB, watering hole, drive-by, malicious ad)."),
    ("exploit", "Exploitation", "Triggering the exploit — vulnerability/macro/trust abuse to execute code."),
    ("install", "Installation", "Establishing persistence on the host — backdoor, service, scheduled task, registry key."),
    ("c2", "Command & Control", "Beacon to attacker infrastructure for control and tasking."),
    ("actions", "Actions on Objectives", "Lateral movement, credential dumping, data theft, ransomware, sabotage."),
]
PHASE_IDS = {p[0] for p in KILL_CHAIN_PHASES}


# =============================================================================
# UseCase + Rule data model
# =============================================================================

@dataclass
class UseCase:
    title: str
    description: str
    kill_chain: str
    techniques: list  # [(id, name)]
    data_models: list  # ["Endpoint.Processes", "Network_Traffic"]
    splunk_spl: str
    defender_kql: str
    sentinel_kql: str = ""           # Microsoft Sentinel KQL — uses TimeGenerated
    sigma_yaml: str = ""              # Optional platform-neutral Sigma rule
    datadog_query: str = ""           # Datadog Cloud SIEM logs query — wrapped
                                      # in Cloud SIEM rule boilerplate at
                                      # rule-pack export time. Empty when the
                                      # detection isn't expressible on Datadog
                                      # telemetry (e.g. only Microsoft-Defender-
                                      # specific tables are available).
    confidence: str = "Medium"
    # Tier classification:
    #   "alerting" — high-fidelity. Specific IOCs, named binaries, threshold
    #                or temporal correlation, statistically anomalous. Safe
    #                to wire to a SIEM rule with normal triage SLA.
    #   "hunting"  — starter content. Returns rows that need analyst review;
    #                will produce false positives without environment tuning.
    # Default to hunting to keep the bar conservative — opt UCs into
    # alerting only when the logic clearly meets that bar.
    tier: str = "hunting"
    # Estimated false-positive rate. One of:
    #   "low"     — <1 fire per week per 10K endpoints in a tuned environment
    #   "medium"  — 1-10 fires per week (still actionable)
    #   "high"    — >10 fires per week (hunt only, do not alert)
    #   "unknown" — not yet measured (default; bias toward hunting)
    fp_rate_estimate: str = "unknown"
    # Required telemetry — UC will return zero rows without these data sources.
    # Helps SOC triage whether they have coverage before deploying. Free-form
    # list of strings, e.g. ["Sysmon EID 1", "Defender DeviceProcessEvents",
    # "EDR process telemetry", "M365 EmailEvents"].
    required_telemetry: list = field(default_factory=list)


def _infer_tier_from_query(spl: str, kql: str, confidence: str) -> str:
    """Heuristic tier classifier for UCs that don't set tier explicitly.

    Returns "alerting" if the query has any of: temporal correlation
    (between (T1 .. T1+Ns)), threshold (count > N / dcount > N), specific
    binary list, hash/IOC IN-list, or anomaly-detection language. Otherwise
    "hunting" — return-rows queries that need an analyst to triage.
    """
    blob = (spl or "") + "\n" + (kql or "")
    blob_l = blob.lower()
    alerting_signals = [
        # Temporal correlation
        " between (", "datetime_diff(", "earliest(_time)", "latest(_time)",
        # Thresholds
        "count > ", "count>=", "count >=", " sum(count) >",
        "dcount(", "dc(", "files > ", "events > ", "uniq",
        # Anomaly statistics
        "stdev(", "stdev_delta", "avg(delta", "avg_delta",
        # Specific IOC substitution slots (UC fires only when IOCs present)
        "__cve_list__", "__ip_list__", "__domain_list__", "__hash_list__",
        # Specific named-binary hunts
        " in (\"", " in~ (\"", "filename in~", "process_name in (",
        # MFA / brute-force rate
        "attempts > ", "logoncount", "mfaprompts >",
    ]
    if any(s in blob_l for s in alerting_signals):
        return "alerting"
    if (confidence or "").lower() == "high" and "data_models=endpoint.processes" in blob_l.replace(" ",""):
        return "alerting"
    return "hunting"


@dataclass
class Rule:
    name: str
    triggers: list  # list of substrings (case-insensitive). ANY-match.
    use_cases: list  # callables or dicts producing UseCase(s)


def _tech(*pairs):
    return [(t.split("|")[0], t.split("|")[1]) for t in pairs]


# =============================================================================
# Use case + rule loader — reads YAML files from use_cases/ and rules/
# =============================================================================

USE_CASES_DIR = Path(__file__).parent / "use_cases"
RULES_DIR = Path(__file__).parent / "rules"


def _load_uc_from_yaml(path):
    import yaml as _yaml
    doc = _yaml.safe_load(path.read_text(encoding="utf-8"))
    if not doc or not isinstance(doc, dict):
        return None
    impls = doc.get("implementations") or []
    dms = doc.get("data_models") or {}
    splunk_dms = dms.get("splunk") or []
    defender_tables = dms.get("defender") or []
    flat_dms = list(splunk_dms) + [t for t in defender_tables if t not in splunk_dms]
    techs = [(t["id"], t["name"]) for t in (doc.get("mitre_attack") or [])]
    spl = (doc.get("splunk_spl") or "") if "splunk" in impls else ""
    kql = (doc.get("defender_kql") or "") if "defender" in impls else ""
    # Sentinel is a separate platform — accept it as an `implementations` value
    # OR as an explicit `sentinel_kql` field (back-compat with legacy UCs that
    # only carried Defender + Splunk).
    sentinel_kql = (doc.get("sentinel_kql") or "")
    if sentinel_kql and "sentinel" not in impls:
        impls.add("sentinel")
    # Sigma is optional. UCs that don't fit Sigma's single-event model
    # leave the field empty; UCs that do, can either embed the Sigma
    # body inline or point at sigma_rules/<file>.yml via `sigma_id`.
    sigma_yaml = (doc.get("sigma_yaml") or "")
    sigma_id = (doc.get("sigma_id") or "").strip()
    if not sigma_yaml and sigma_id:
        sigma_path = Path(__file__).parent / "sigma_rules" / f"{sigma_id}.yml"
        if sigma_path.exists():
            sigma_yaml = sigma_path.read_text(encoding="utf-8")
    if sigma_yaml and "sigma" not in impls:
        impls.add("sigma")
    # Datadog Cloud SIEM is a separate platform; accepted either via the
    # `implementations` list or directly as a `datadog_query` field. Same
    # back-compat shape as Sentinel.
    datadog_query = (doc.get("datadog_query") or "")
    if datadog_query and "datadog" not in impls:
        impls.add("datadog")
    confidence = doc.get("confidence", "Medium")
    # Tier: explicit field wins; otherwise infer from query shape.
    tier = (doc.get("tier") or "").strip().lower() or _infer_tier_from_query(spl, kql, confidence)
    if tier not in ("alerting", "hunting"):
        tier = "hunting"
    fp_rate = (doc.get("fp_rate_estimate") or "unknown").strip().lower()
    if fp_rate not in ("low", "medium", "high", "unknown"):
        fp_rate = "unknown"
    req_telemetry = doc.get("required_telemetry") or []
    if not isinstance(req_telemetry, list):
        req_telemetry = [str(req_telemetry)]
    return UseCase(
        title=doc.get("title", ""),
        description=(doc.get("description") or "").strip(),
        kill_chain=doc.get("kill_chain", "actions"),
        techniques=techs,
        data_models=flat_dms,
        splunk_spl=spl,
        defender_kql=kql,
        sentinel_kql=sentinel_kql,
        sigma_yaml=sigma_yaml,
        datadog_query=datadog_query,
        confidence=confidence,
        tier=tier,
        fp_rate_estimate=fp_rate,
        required_telemetry=[str(t) for t in req_telemetry],
    )


def _load_rule_from_yaml(path, uc_lookup):
    import yaml as _yaml
    doc = _yaml.safe_load(path.read_text(encoding="utf-8"))
    if not doc:
        return None
    fires = []
    for uc_id in doc.get("fires") or []:
        uc = uc_lookup.get(uc_id)
        if uc:
            fires.append(uc)
    return Rule(
        name=doc.get("name", path.stem),
        triggers=list(doc.get("triggers") or []),
        use_cases=fires,
    )


def _load_catalog():
    """Load all UseCases and Rules from YAML, expose them at module level."""
    if not USE_CASES_DIR.exists():
        print(f"[!] {USE_CASES_DIR} not found — using inline catalog (legacy mode)")
        return None, None
    use_cases = {}
    for path in sorted(USE_CASES_DIR.rglob("*.yml")):
        if path.name.startswith("_") or path.name == "SCHEMA.md":
            continue
        uc = _load_uc_from_yaml(path)
        if uc is None:
            continue
        uc_id = path.stem  # filename = id
        use_cases[uc_id] = uc
    rules = []
    if RULES_DIR.exists():
        for path in sorted(RULES_DIR.glob("*.yml")):
            r = _load_rule_from_yaml(path, use_cases)
            if r and r.use_cases:
                rules.append(r)
    return use_cases, rules


_LOADED_UCS, _LOADED_RULES = _load_catalog()
if _LOADED_UCS:
    # Expose every loaded use case as a module-level variable so the matrix
    # builder, validator, and renderer continue to work as before.
    for _uc_id, _uc in _LOADED_UCS.items():
        globals()[_uc_id] = _uc
    # Drop the loop variables — otherwise the leftover `_uc` lingers in
    # module globals and the matrix builder picks it up as an extra UseCase.
    del _uc_id, _uc
    print(f"[*] Loaded {len(_LOADED_UCS)} use cases from {USE_CASES_DIR}")
    print(f"[*] Loaded {len(_LOADED_RULES)} rules from {RULES_DIR}")


# =============================================================================
# Inline use case templates (legacy) — these get OVERRIDDEN at the end of the
# rules block by the YAML-loaded versions. Will be deleted entirely once we're
# fully on YAML and have git-committed the use_cases/ tree.
# =============================================================================

UC_PHISH_LINK = UseCase(
    title="Suspicious URL click in email — phishing landing page",
    description=(
        "User followed a link from an external email to an uncategorized / "
        "young-domain page. Pivots from the Email DM onto the Web DM to flag the "
        "click-through chain that typically precedes credential theft."
    ),
    kill_chain="delivery",
    techniques=_tech("T1566.002|Spearphishing Link", "T1204.001|User Execution: Malicious Link"),
    data_models=["Email.All_Email", "Web"],
    splunk_spl="""\
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.action="delivered" AND All_Email.url!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.url, All_Email.subject
| rex field=All_Email.url "https?://(?<email_domain>[^/]+)"
| join type=inner email_domain
    [| tstats `summariesonly` count
        from datamodel=Web
        where Web.action="allowed"
        by Web.src, Web.dest, Web.url, Web.user
     | rex field=Web.url "https?://(?<email_domain>[^/]+)"]
| stats values(All_Email.subject) as subject, values(Web.url) as clicked_url,
        earliest(_time) as first_seen, latest(_time) as last_seen
        by All_Email.recipient, email_domain
""",
    defender_kql="""\
let LookbackDays = 7d;
let DeliveredEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress,
              EmailTimestamp = Timestamp;
EmailUrlInfo
| where Timestamp > ago(LookbackDays)
| join kind=inner DeliveredEmails on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "ClickAllowed"
    | project Url, ClickTimestamp = Timestamp, AccountUpn, IPAddress
  ) on Url
| project ClickTimestamp, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, IPAddress
| order by ClickTimestamp desc
""",
    confidence="High",
)

UC_PHISH_ATTACH = UseCase(
    title="Email attachment opened from external sender",
    description="Attachment delivery + execution by recipient — most common malware initial access.",
    kill_chain="delivery",
    techniques=_tech("T1566.001|Spearphishing Attachment", "T1204.002|User Execution: Malicious File"),
    data_models=["Email.All_Email", "Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
""",
    defender_kql="""\
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
""",
    confidence="High",
)

UC_OFFICE_CHILD = UseCase(
    title="Office app spawning script/LOLBin child process",
    description="Classic macro/exploit pattern — Office app launching cmd/powershell/wmic/regsvr32.",
    kill_chain="exploit",
    techniques=_tech("T1059.001|PowerShell", "T1059.005|Visual Basic", "T1218|System Binary Proxy Execution"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
""",
    confidence="High",
)

UC_PS_OBFUSCATED = UseCase(
    title="PowerShell encoded / obfuscated command",
    description="Encoded or obfuscated PowerShell — common across loaders, recon, and post-exploitation.",
    kill_chain="exploit",
    techniques=_tech("T1059.001|PowerShell", "T1027|Obfuscated Files or Information"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
""",
    confidence="High",
)

UC_LSASS = UseCase(
    title="LSASS process access / dump (credential theft)",
    description="Mimikatz, comsvcs.dll MiniDump, or any non-Windows process opening LSASS.",
    kill_chain="actions",
    techniques=_tech("T1003.001|LSASS Memory", "T1003|OS Credential Dumping"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
""",
    confidence="High",
)

UC_BEACONING = UseCase(
    title="Beaconing — periodic outbound to small set of destinations",
    description="C2 channel detection via inter-beacon-time stddev / fan-out to single dest.",
    kill_chain="c2",
    techniques=_tech("T1071.001|Web Protocols", "T1071.004|DNS"),
    data_models=["Network_Traffic.All_Traffic"],
    splunk_spl="""\
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
""",
    defender_kql="""\
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
""",
    confidence="Medium",
)

UC_DNS_TUNNEL = UseCase(
    title="DNS tunneling / TXT-heavy domain queries",
    description="Long subdomain labels + frequent queries to a single 2LD = DNS C2/exfil.",
    kill_chain="c2",
    techniques=_tech("T1071.004|DNS", "T1048.003|Exfiltration Over Unencrypted Non-C2 Protocol"),
    data_models=["Network_Resolution.DNS"],
    splunk_spl="""\
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\\w-]+\\.[\\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
""",
    defender_kql="""\
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
""",
    confidence="Medium",
)

UC_SCHEDULED_TASK = UseCase(
    title="Scheduled task created with suspicious image / encoded args",
    description="schtasks.exe /create or Microsoft-Windows-TaskScheduler EventID 4698 with LOLBin actions.",
    kill_chain="install",
    techniques=_tech("T1053.005|Scheduled Task"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\\Users\\Public*"
        OR Processes.process="*\\AppData\\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\\Users\\Public","\\AppData\\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
""",
    confidence="High",
)

UC_SERVICE_PERSIST = UseCase(
    title="Service install for persistence — sc.exe / new service registry write",
    description=(
        "Service install with binPath pointing to user-writeable path or LOLBin. "
        "Detects via process telemetry (sc.exe create) and registry "
        "(HKLM\\SYSTEM\\CurrentControlSet\\Services\\* writes)."
    ),
    kill_chain="install",
    techniques=_tech("T1543.003|Windows Service"),
    data_models=["Endpoint.Processes", "Endpoint.Registry"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\\Users\\*" OR Processes.process="*\\AppData\\*"
        OR Processes.process="*\\ProgramData\\*" OR Processes.process="*\\Temp\\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Registry
        where Registry.registry_path="*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\*"
          AND Registry.registry_value_name="ImagePath"
          AND (Registry.registry_value_data="*\\Users\\*"
            OR Registry.registry_value_data="*\\AppData\\*"
            OR Registry.registry_value_data="*\\Temp\\*")
        by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.user
     | `drop_dm_object_name(Registry)`]
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| where ProcessCommandLine matches regex @"(?i)(\\Users\\|\\AppData\\|\\ProgramData\\|\\Temp\\)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
""",
    confidence="High",
)

UC_VULN_EXPOSURE = UseCase(
    title="Asset exposure — vulnerability matches article CVE(s)",
    description="Match vulnerability scanner output to the CVE(s) named in the article.",
    kill_chain="recon",
    techniques=_tech("T1190|Exploit Public-Facing Application"),
    data_models=["Vulnerabilities"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Vulnerabilities
    where Vulnerabilities.signature IN (__CVE_LIST__)
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
""",
    defender_kql="""\
DeviceTvmSoftwareVulnerabilities
| where CveId in~ (__CVE_LIST__)
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
""",
    confidence="High",
)

UC_NETWORK_IOC = UseCase(
    title="Network connections to article IPs / domains",
    description="Outbound traffic to attacker infrastructure named in the article.",
    kill_chain="c2",
    techniques=_tech("T1071|Application Layer Protocol"),
    data_models=["Network_Traffic.All_Traffic", "Web", "Network_Resolution.DNS"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest IN (__IP_LIST__)
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| append
    [| tstats `summariesonly` count from datamodel=Web
        where Web.dest IN (__DOMAIN_LIST__)
        by Web.src, Web.dest, Web.url, Web.user
     | `drop_dm_object_name(Web)`]
| append
    [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
        where DNS.query IN (__DOMAIN_LIST__)
        by DNS.src, DNS.query, DNS.answer
     | `drop_dm_object_name(DNS)`]
""",
    defender_kql="""\
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in (__IP_LIST__) or RemoteUrl has_any (__DOMAIN_LIST__)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
""",
    confidence="High",
)

UC_HASH_IOC = UseCase(
    title="File hash IOCs — endpoint file/process match",
    description="Match SHA256/SHA1/MD5 named in the article against EDR file/process telemetry.",
    kill_chain="install",
    techniques=_tech("T1027|Obfuscated Files or Information"),
    data_models=["Endpoint.Filesystem", "Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN (__HASH_LIST__)
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.process_hash IN (__HASH_LIST__)
        by Processes.dest, Processes.user, Processes.process_name, Processes.process_hash
     | `drop_dm_object_name(Processes)`]
""",
    defender_kql="""\
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ (__HASH_LIST__) or SHA1 in~ (__HASH_LIST__) or MD5 in~ (__HASH_LIST__)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
""",
    confidence="High",
)

UC_RANSOM_ENCRYPT = UseCase(
    title="Ransomware-style mass file rename / extension change",
    description="Threshold detection: many files renamed in short window, often with new extension.",
    kill_chain="actions",
    techniques=_tech("T1486|Data Encrypted for Impact"),
    data_models=["Endpoint.Filesystem"],
    splunk_spl="""\
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
""",
    defender_kql="""\
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
| order by files desc
""",
    confidence="Medium",
)

UC_LATERAL_PSEXEC = UseCase(
    title="Remote service execution — PsExec / SMB lateral movement",
    description="psexec / paexec / smbexec / wmic /node — service install over SMB from remote host.",
    kill_chain="actions",
    techniques=_tech("T1021.002|SMB/Windows Admin Shares", "T1569.002|Service Execution"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
""",
    confidence="High",
)

UC_OAUTH_ABUSE = UseCase(
    title="OAuth consent / suspicious app grant",
    description="Cloud identity abuse: app gets high-priv scopes, often via consent phishing.",
    kill_chain="actions",
    techniques=_tech("T1528|Steal Application Access Token", "T1098.001|Account Manipulation: Additional Cloud Credentials"),
    data_models=["Authentication.Authentication"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
""",
    defender_kql="""\
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
""",
    confidence="High",
)

UC_MFA_FATIGUE = UseCase(
    title="MFA fatigue / push-bombing",
    description="Many MFA pushes to same user in short window — suggests adversary attempting approval-fatigue.",
    kill_chain="actions",
    techniques=_tech("T1621|Multi-Factor Authentication Request Generation"),
    data_models=["Authentication.Authentication"],
    splunk_spl="""\
| tstats `summariesonly` count from datamodel=Authentication.Authentication
    where Authentication.action="failure" AND Authentication.signature="*MFA*"
    by _time span=5m, Authentication.user, Authentication.src
| `drop_dm_object_name(Authentication)`
| where count > 10
""",
    defender_kql="""\
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode in (50074, 50076, 50158, 50125, 50097)
| extend MfaPrompt = AuthenticationRequirement == "multiFactorAuthentication"
| where MfaPrompt
| summarize attempts = count(), distinct_ips = dcount(IPAddress)
    by AccountUpn, bin(Timestamp, 5m)
| where attempts > 10
| order by attempts desc
""",
    confidence="High",
)

UC_SUPPLY_CHAIN = UseCase(
    title="Trusted vendor binary / installer launching unusual children",
    description="Supply-chain trojan signal: legitimate signed binary spawning script interpreters or exotic LOLBins.",
    kill_chain="exploit",
    techniques=_tech("T1195.002|Compromise Software Supply Chain"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN (__VENDOR_BINS__)
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (__VENDOR_BINS__)
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
""",
    confidence="Medium",
)

UC_FAKECAPTCHA = UseCase(
    title="Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)",
    description="Browser-pasted PowerShell launched from explorer/Run dialog — ClickFix social engineering.",
    kill_chain="exploit",
    techniques=_tech("T1204.004|User Execution: Malicious Copy and Paste", "T1059.001|PowerShell"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
""",
    confidence="High",
)

UC_BROWSER_STEALER = UseCase(
    title="Infostealer — non-browser process accessing browser cookie/login DBs",
    description="Stealers (RedLine, Lumma, Vidar, Atomic) read Login Data / cookies SQLite from Chrome/Edge/Firefox.",
    kill_chain="actions",
    techniques=_tech("T1539|Steal Web Session Cookie", "T1555.003|Credentials from Web Browsers"),
    data_models=["Endpoint.Filesystem"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Login Data*"
        OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Cookies*"
        OR Filesystem.file_path="*\\Microsoft\\Edge\\User Data\\*\\Login Data*"
        OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*\\logins.json*"
        OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
""",
    defender_kql="""\
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\Google\\Chrome\\User Data\\","\\Microsoft\\Edge\\User Data\\","\\Mozilla\\Firefox\\Profiles\\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
""",
    confidence="High",
)

UC_TEAMS_VISHING = UseCase(
    title="Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator",
    description="External Teams chat where displayName contains 'helpdesk' or 'IT support' — common 2024+ vishing pattern (Storm-1811, Black Basta, UNC6692). No CIM data model maps to Teams chats; uses raw O365 audit logs.",
    kill_chain="delivery",
    techniques=_tech("T1566.004|Phishing: Spearphishing Voice", "T1566|Phishing"),
    data_models=["O365 audit (raw)"],
    splunk_spl="""\
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
""",
    defender_kql="""\
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
""",
    confidence="High",
)

UC_RMM_TOOLS = UseCase(
    title="RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard",
    description="ConnectWise / AnyDesk / TeamViewer / ScreenConnect / Atera installed outside IT change windows = common tradecraft for ransomware affiliates and IT-helpdesk impersonators.",
    kill_chain="install",
    techniques=_tech("T1219|Remote Access Software"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
""",
    confidence="High",
)

UC_BROWSER_EXT = UseCase(
    title="Suspicious browser extension installation",
    description="Side-loaded / unsigned extensions, often masquerading as wallets, productivity tools.",
    kill_chain="install",
    techniques=_tech("T1176|Browser Extensions"),
    data_models=["Endpoint.Registry"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\\Software\\Google\\Chrome\\Extensions\\*"
        OR Registry.registry_path="*\\Software\\Microsoft\\Edge\\Extensions\\*"
        OR Registry.registry_path="*\\Software\\Mozilla\\Firefox\\Extensions\\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
""",
    defender_kql="""\
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("\\Software\\Google\\Chrome\\Extensions\\","\\Software\\Microsoft\\Edge\\Extensions\\","\\Software\\Mozilla\\Firefox\\Extensions\\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
""",
    confidence="Medium",
)

UC_CRYPTO_WALLET = UseCase(
    title="Crypto-wallet file/keystore access by non-wallet process",
    description="Stealers / wallet drainers read keystore.json, MetaMask, Exodus, Atomic, Phantom data.",
    kill_chain="actions",
    techniques=_tech("T1005|Data from Local System"),
    data_models=["Endpoint.Filesystem"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\\Ethereum\\keystore\\*"
        OR Filesystem.file_path="*\\Bitcoin\\wallet.dat"
        OR Filesystem.file_path="*\\Exodus\\exodus.wallet*"
        OR Filesystem.file_path="*\\Electrum\\wallets\\*"
        OR Filesystem.file_path="*\\MetaMask\\*"
        OR Filesystem.file_path="*\\Phantom\\*"
        OR Filesystem.file_path="*\\Atomic\\Local Storage\\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
""",
    defender_kql="""\
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\Ethereum\\keystore\\","\\Bitcoin\\","\\Exodus\\","\\Electrum\\wallets\\","\\MetaMask\\","\\Phantom\\","\\Atomic\\Local Storage\\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
""",
    confidence="High",
)


# =============================================================================
# Rules — link narrative phrases to use cases
# =============================================================================

RULES = [
    Rule("Phishing — link",
         ["phishing email", "phishing link", "spear-phishing", "spearphishing", "spear phishing",
          "credential harvest", "credential phishing", "fake login", "fake captcha",
          "clickfix", "click-fix", "click fix"],
         [UC_PHISH_LINK, UC_FAKECAPTCHA]),

    Rule("Phishing — attachment",
         ["malicious attachment", "weaponized document", "weaponised document",
          "macro-laden", "vba macro", "office macro", "malicious doc"],
         [UC_PHISH_ATTACH, UC_OFFICE_CHILD]),

    Rule("Generic phishing — assume both modes",
         ["phishing", "phish "],
         [UC_PHISH_LINK, UC_PHISH_ATTACH, UC_OFFICE_CHILD]),

    Rule("PowerShell / scripting",
         ["powershell", "encoded command", "obfuscated", "iex", "invoke-expression"],
         [UC_PS_OBFUSCATED]),

    Rule("Office / macro",
         ["macro", "office document", "word document", "excel macro", "office attachment"],
         [UC_OFFICE_CHILD]),

    Rule("Credential dumping / LSASS",
         ["credential dumping", "lsass", "mimikatz", "sekurlsa", "comsvcs"],
         [UC_LSASS]),

    Rule("Beaconing / C2",
         ["c2 ", "command and control", "command-and-control", "beacon", "cobalt strike",
          "sliver", "brute ratel", "havoc framework"],
         [UC_BEACONING, UC_NETWORK_IOC]),

    Rule("DNS C2 / tunneling",
         ["dns tunneling", "dns tunnel", "dns-based c2", "dns exfil"],
         [UC_DNS_TUNNEL]),

    Rule("Persistence — scheduled task",
         ["scheduled task", "schtasks", "task scheduler"],
         [UC_SCHEDULED_TASK]),

    Rule("Persistence — service",
         ["new service", "service install", "service registry"],
         [UC_SERVICE_PERSIST]),

    Rule("CVE / vulnerability",
         ["cve-", "vulnerability", "exploited flaw", "kev catalog", "patched flaw",
          "rce ", "remote code execution", "exploit chain", "zero-day", "zero day", "0-day"],
         [UC_VULN_EXPOSURE]),

    Rule("Ransomware",
         ["ransomware", "encrypts files", "ransom note", "double extortion",
          "lockbit", "blackcat", "alphv", "akira", "play ransomware", "rhysida",
          "ransomhub", "qilin", "8base", "medusa ransomware", "clop", "cl0p",
          "black basta", "blackbasta"],
         [UC_RANSOM_ENCRYPT, UC_LSASS, UC_LATERAL_PSEXEC]),

    Rule("Lateral movement",
         ["lateral movement", "psexec", "smbexec", "wmic /node", "remote service"],
         [UC_LATERAL_PSEXEC]),

    Rule("OAuth / consent abuse",
         ["oauth", "consent phishing", "illicit consent", "token theft", "app registration"],
         [UC_OAUTH_ABUSE]),

    Rule("MFA bombing",
         ["mfa fatigue", "mfa bombing", "push bombing", "push fatigue", "mfa-bombing"],
         [UC_MFA_FATIGUE]),

    Rule("Supply chain",
         ["supply chain", "supply-chain", "trojanized installer", "trojanised installer",
          "compromised software", "package compromise", "trojanized sumatrapdf",
          "trojanised sumatrapdf", "weaponized installer"],
         [UC_SUPPLY_CHAIN]),

    Rule("Browser stealer / cookie theft",
         ["infostealer", "info stealer", "stealer malware", "redline stealer",
          "lumma stealer", "vidar stealer", "atomic stealer", "stealc", "risepro",
          "browser cookies", "session cookie", "session hijack", "browser session"],
         [UC_BROWSER_STEALER]),

    Rule("Microsoft Teams vishing / IT-helpdesk impersonation",
         ["microsoft teams", "teams chat", "it help desk", "it helpdesk",
          "help desk impersonat", "service desk impersonat", "tech support impersonat",
          "impersonating it"],
         [UC_TEAMS_VISHING, UC_RMM_TOOLS]),

    Rule("RMM abuse",
         ["anydesk", "teamviewer", "screenconnect", "connectwise", "atera",
          "splashtop", "rustdesk", "ninjarmm", "ninjaone", "kaseya", "remote access tool",
          "rmm tool", "rmm software"],
         [UC_RMM_TOOLS]),

    Rule("Browser extensions",
         ["malicious extension", "browser extension", "fake wallet", "fake extension",
          "chrome extension", "edge extension", "rogue extension"],
         [UC_BROWSER_EXT, UC_BROWSER_STEALER]),

    Rule("Crypto wallet",
         ["crypto wallet", "wallet drainer", "metamask", "phantom wallet",
          "exodus wallet", "fakewallet", "fake wallet", "cryptocurrency theft"],
         [UC_CRYPTO_WALLET, UC_BROWSER_STEALER]),
]

# --- YAML override --------------------------------------------------------
# If use_cases/ and rules/ YAML are present, they win over the inline
# definitions above. Going forward, edit YAML files only — the inline block
# is kept as a runtime fallback / git-blame reference.
if _LOADED_UCS:
    for _uc_id, _uc in _LOADED_UCS.items():
        globals()[_uc_id] = _uc
    del _uc_id, _uc
    if _LOADED_RULES:
        RULES = list(_LOADED_RULES)


# =============================================================================
# Article narrative inference
# =============================================================================

NARRATIVE_KILLCHAIN = [
    # text -> set of phases
    (re.compile(r"\bphishing|spear-?phish|email|smis?hing|vishing\b", re.I), {"delivery"}),
    (re.compile(r"\bsupply.?chain|trojanized|trojanised|installer\b", re.I), {"delivery", "exploit"}),
    (re.compile(r"\bcve-|exploit|0-?day|zero-?day|rce|public-?facing\b", re.I), {"exploit"}),
    (re.compile(r"\bmacro|office\s+(?:doc|file)|vbs\b", re.I), {"exploit"}),
    (re.compile(r"\bdll|rundll32|regsvr32|mshta|powershell|cmd\.exe\b", re.I), {"exploit"}),
    (re.compile(r"\bscheduled\s+task|service\s+install|registry\s+run|persistence\b", re.I), {"install"}),
    (re.compile(r"\bbackdoor|implant|rat\b|remote\s+access\s+trojan", re.I), {"install", "c2"}),
    (re.compile(r"\bbeacon|c2|command\s*and\s*control|callback\b", re.I), {"c2"}),
    (re.compile(r"\bcredential|lsass|mimikatz|kerberos|ntds\b", re.I), {"actions"}),
    (re.compile(r"\blateral\s*movement|psexec|smb\s*exec|wmi\b", re.I), {"actions"}),
    (re.compile(r"\bransom|encrypt(?:s|ed)?\s*files\b", re.I), {"actions"}),
    (re.compile(r"\bdata\s*theft|exfiltrat|stealer\b", re.I), {"actions"}),
    (re.compile(r"\brecon|scan|enumerat\b", re.I), {"recon"}),
    (re.compile(r"\bweaponized|weaponised|weaponi[sz]ation\b", re.I), {"weapon"}),
]

# Common attacker chain implication: if Initial Access (delivery) is detected,
# attackers will typically execute, install, beacon, and act on objectives.
INFER_FROM_PHASE = {
    "delivery": {"exploit", "install", "c2"},
    "exploit": {"install", "c2"},
    "install": {"c2", "actions"},
    "c2": {"actions"},
}


def detect_kill_chain(text: str):
    text_l = text.lower()
    found = set()
    for rx, phases in NARRATIVE_KILLCHAIN:
        if rx.search(text):
            found |= phases
    inferred = set()
    for ph in list(found):
        inferred |= INFER_FROM_PHASE.get(ph, set())
    return found, inferred - found


# =============================================================================
# Threat profile — pulls together a richer summary per article
# =============================================================================

ATTACK_KEYWORD_TO_TID = {
    "powershell": ("T1059.001", "PowerShell"),
    "cmd.exe": ("T1059.003", "Windows Command Shell"),
    "wmi": ("T1047", "Windows Management Instrumentation"),
    "scheduled task": ("T1053.005", "Scheduled Task"),
    "lsass": ("T1003.001", "LSASS Memory"),
    "ntds": ("T1003.003", "NTDS"),
    "kerberoast": ("T1558.003", "Kerberoasting"),
    "kerberos": ("T1558", "Steal or Forge Kerberos Tickets"),
    "pass-the-hash": ("T1550.002", "Pass the Hash"),
    "pass-the-ticket": ("T1550.003", "Pass the Ticket"),
    "rdp": ("T1021.001", "Remote Desktop Protocol"),
    "smb": ("T1021.002", "SMB/Windows Admin Shares"),
    "winrm": ("T1021.006", "Windows Remote Management"),
    "psexec": ("T1021.002", "SMB/Windows Admin Shares"),
    "registry run key": ("T1547.001", "Registry Run Keys / Startup Folder"),
    "dll sideloading": ("T1574.002", "DLL Side-Loading"),
    "rundll32": ("T1218.011", "Rundll32"),
    "regsvr32": ("T1218.010", "Regsvr32"),
    "mshta": ("T1218.005", "Mshta"),
    "office macro": ("T1059.005", "Visual Basic"),
    "phishing email": ("T1566.001", "Spearphishing Attachment"),
    "phishing link": ("T1566.002", "Spearphishing Link"),
    "phishing": ("T1566", "Phishing"),
    "spearphishing": ("T1566.002", "Spearphishing Link"),
    "credential dumping": ("T1003", "OS Credential Dumping"),
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "supply chain": ("T1195.002", "Compromise Software Supply Chain"),
    "browser cookies": ("T1539", "Steal Web Session Cookie"),
    "session cookie": ("T1539", "Steal Web Session Cookie"),
    "ad cs": ("T1649", "Steal or Forge Authentication Certificates"),
    "service install": ("T1543.003", "Windows Service"),
    "rce": ("T1190", "Exploit Public-Facing Application"),
    "remote code execution": ("T1190", "Exploit Public-Facing Application"),
    "exploit public-facing": ("T1190", "Exploit Public-Facing Application"),
    "encoded command": ("T1027", "Obfuscated Files or Information"),
    "obfuscat": ("T1027", "Obfuscated Files or Information"),
    "mfa fatigue": ("T1621", "Multi-Factor Authentication Request Generation"),
    "consent phishing": ("T1528", "Steal Application Access Token"),
    "oauth": ("T1528", "Steal Application Access Token"),
    "infostealer": ("T1555.003", "Credentials from Web Browsers"),
    "stealer": ("T1555.003", "Credentials from Web Browsers"),
    "anydesk": ("T1219", "Remote Access Software"),
    "teamviewer": ("T1219", "Remote Access Software"),
    "screenconnect": ("T1219", "Remote Access Software"),
    "rmm tool": ("T1219", "Remote Access Software"),
    "browser extension": ("T1176", "Browser Extensions"),
    "fake captcha": ("T1204.004", "User Execution: Malicious Copy and Paste"),
    "clickfix": ("T1204.004", "User Execution: Malicious Copy and Paste"),
    "smishing": ("T1660", "Phishing"),
    "trojan": ("T1204.002", "Malicious File"),
}


def infer_techniques(text: str, explicit: list) -> list:
    found = {}  # id -> name
    for tid in explicit:
        found[tid] = tid
    text_l = text.lower()
    for kw, (tid, name) in ATTACK_KEYWORD_TO_TID.items():
        if kw in text_l:
            found[tid] = name
    return sorted(found.items())


# =============================================================================
# Render: substitute placeholders in templated SPL/KQL
# =============================================================================

def fmt_list(values, sep=", ", quote='"'):
    return sep.join(f"{quote}{v}{quote}" for v in values)


def parameterize(text: str, ind: dict) -> str:
    """Substitute IOC placeholders. Returns empty string if the query
    references an IOC class the article doesn't have — caller-side
    suppression is preferred (see select_use_cases) but this is a
    safety net so we never ship `IN ("-")` placeholder queries."""
    cves = ind["cves"]
    ips = ind["ips"]
    domains = ind["domains"][:10]
    hashes = ind["sha256"] + ind["sha1"] + ind["md5"]
    if "__CVE_LIST__" in text and not cves: return ""
    if "__IP_LIST__" in text and not ips and "__DOMAIN_LIST__" not in text: return ""
    if "__DOMAIN_LIST__" in text and not domains and "__IP_LIST__" not in text: return ""
    if "__IP_LIST__" in text and "__DOMAIN_LIST__" in text and not (ips or domains): return ""
    if "__HASH_LIST__" in text and not hashes: return ""
    text = text.replace("__CVE_LIST__", fmt_list(cves))
    text = text.replace("__IP_LIST__", fmt_list(ips) if ips else '""')
    text = text.replace("__DOMAIN_LIST__", fmt_list(domains) if domains else '""')
    text = text.replace("__HASH_LIST__", fmt_list(hashes))
    text = text.replace("__VENDOR_BINS__", '"setup.exe","installer.exe","update.exe"')
    return text


def select_use_cases(article_text: str, ind: dict) -> list:
    activated = []
    seen_titles = set()
    text_l = article_text.lower()
    has_cve = bool(ind.get("cves"))
    has_netioc = bool(ind.get("ips") or ind.get("domains"))
    has_hash = bool(ind.get("sha256") or ind.get("sha1") or ind.get("md5"))
    # Rule-fired UCs only get added when their target IOC class is actually
    # present. We never want to ship a vuln-exposure / network-IOC / hash-IOC
    # use case with placeholder values like "-" or "0.0.0.0" — better to say
    # "no actionable hunt for this category" by leaving the UC out entirely.
    iocless_titles = {
        UC_VULN_EXPOSURE.title: has_cve,
        UC_NETWORK_IOC.title:   has_netioc,
        UC_HASH_IOC.title:      has_hash,
    }
    for rule in RULES:
        if any(t in text_l for t in rule.triggers):
            for uc in rule.use_cases:
                if uc.title in iocless_titles and not iocless_titles[uc.title]:
                    continue  # would render placeholder query — skip
                if uc.title not in seen_titles:
                    activated.append(uc)
                    seen_titles.add(uc.title)
    if has_cve and UC_VULN_EXPOSURE.title not in seen_titles:
        activated.append(UC_VULN_EXPOSURE)
        seen_titles.add(UC_VULN_EXPOSURE.title)
    if has_netioc and UC_NETWORK_IOC.title not in seen_titles:
        activated.append(UC_NETWORK_IOC)
        seen_titles.add(UC_NETWORK_IOC.title)
    if has_hash and UC_HASH_IOC.title not in seen_titles:
        activated.append(UC_HASH_IOC)
        seen_titles.add(UC_HASH_IOC.title)
    return activated


# =============================================================================
# HTML render
# =============================================================================

HTML_HEAD = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Clankerusecase — Threat-led detection library: Defender KQL, Sentinel KQL, Sigma, Splunk SPL</title>
<link rel="icon" type="image/png" href="https://clankerusecase.com/logo.png">
<link rel="apple-touch-icon" href="https://clankerusecase.com/logo.png">
<link rel="canonical" href="https://clankerusecase.com/">
<meta name="description" content="Open-source threat-led detection library: 2,000+ use cases mapped to MITRE ATT&amp;CK, with Defender KQL, Sentinel KQL, Sigma, and Splunk SPL queries. Auto-pulled from 11+ threat-intel feeds (BleepingComputer, The Hacker News, Microsoft, Talos, ESET, Unit 42, SentinelLabs, Securelist, Lab52, CISA KEV) every 2 hours.">
<meta name="keywords" content="MITRE ATT&amp;CK, Defender KQL, Sentinel KQL, Sigma rules, Splunk SPL, threat hunting, SOC, threat intelligence, detection engineering, CTI, Microsoft Defender Advanced Hunting, Microsoft Sentinel, IOC, indicators of compromise, KQL queries, SPL queries, threat actors, APT, ransomware, phishing, BleepingComputer, Hacker News">
<meta name="author" content="Virtualhaggis">
<meta name="robots" content="index, follow, max-image-preview:large">
<meta name="theme-color" content="#08090a">

<!-- Open Graph / Facebook / LinkedIn -->
<meta property="og:type" content="website">
<meta property="og:site_name" content="Clankerusecase">
<meta property="og:url" content="https://clankerusecase.com/">
<meta property="og:title" content="Clankerusecase — Threat-led detection library for SOC teams">
<meta property="og:description" content="2,000+ MITRE-mapped detections in Defender KQL, Sentinel KQL, Sigma, and Splunk SPL — auto-generated from daily threat-intel feeds. Free, open source, ready to deploy.">
<meta property="og:image" content="https://clankerusecase.com/logo.png">
<meta property="og:image:alt" content="Clankerusecase — production-ready SOC detections from daily threat-intel">
<meta property="og:locale" content="en_GB">

<!-- Twitter / X -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Clankerusecase — Threat-led detection library">
<meta name="twitter:description" content="2,000+ MITRE-mapped detections in Defender KQL, Sentinel KQL, Sigma, and Splunk SPL. Auto-generated from daily threat-intel.">
<meta name="twitter:image" content="https://clankerusecase.com/logo.png">
<meta name="twitter:image:alt" content="Clankerusecase — production-ready SOC detections">

<!-- Structured data — tells Google this is a SoftwareApplication / Dataset
     so search results can surface descriptive snippets and rich cards
     instead of just the raw HTML title. -->
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebSite",
      "@id": "https://clankerusecase.com/#website",
      "url": "https://clankerusecase.com/",
      "name": "Clankerusecase",
      "description": "Open-source threat-led detection library: 2,000+ MITRE-mapped use cases in Defender KQL, Sentinel KQL, Sigma, and Splunk SPL.",
      "publisher": {"@id": "https://clankerusecase.com/#org"},
      "potentialAction": {
        "@type": "SearchAction",
        "target": "https://clankerusecase.com/?q={search_term_string}",
        "query-input": "required name=search_term_string"
      }
    },
    {
      "@type": "Organization",
      "@id": "https://clankerusecase.com/#org",
      "name": "Clankerusecase",
      "url": "https://clankerusecase.com/",
      "logo": "https://clankerusecase.com/logo.png",
      "sameAs": ["https://github.com/Virtualhaggis/usecaseintel"]
    },
    {
      "@type": "Dataset",
      "@id": "https://clankerusecase.com/#dataset",
      "name": "Clankerusecase Detection Library",
      "description": "Daily-refreshed corpus of SOC detection use cases mapped to MITRE ATT&CK, expressed in Defender KQL, Microsoft Sentinel KQL, Sigma, and Splunk SPL. Each detection is tied to a public threat-intel article from BleepingComputer, The Hacker News, Microsoft, Talos, ESET, Unit 42, SentinelLabs, Securelist, Lab52, CISA KEV, or similar source.",
      "creator": {"@id": "https://clankerusecase.com/#org"},
      "license": "https://opensource.org/licenses/MIT",
      "url": "https://clankerusecase.com/",
      "keywords": "MITRE ATT&CK, threat detection, Defender KQL, Sentinel KQL, Sigma, Splunk SPL, threat intelligence, SOC, threat hunting, IOC",
      "isAccessibleForFree": true
    },
    {
      "@type": "SoftwareApplication",
      "name": "Clankerusecase",
      "applicationCategory": "SecurityApplication",
      "operatingSystem": "Web",
      "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
      "description": "Threat-led detection library for SOC teams, threat hunters, and CTI analysts. Free and open source.",
      "url": "https://clankerusecase.com/"
    }
  ]
}
</script>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* =====================================================================
   Theme: Linear-inspired dark UI
   - Flat near-black background; subtle top-of-page accent wash only
   - Inter typography with tight tracking, small body scale
   - Indigo (#5e6ad2) signature accent; purple secondary
   - Hairline 1px borders (rgba white 0.07) instead of heavy frames
   - Restrained shadows — Linear leans on borders, not depth
   - Compact radii (4 / 6 / 8px) for that precision feel
   ===================================================================== */
:root {
  /* Backgrounds — near-black with three elevation steps */
  --bg:#08090a; --bg-grad-1:#0d0e10; --bg-grad-2:#08090a;
  --panel:#16171b; --panel-elev:#1f2024; --panel2:#26272b;
  /* Text — high-contrast on dark; Linear keeps body text very legible */
  --text:#f7f8f8; --muted:#8a8f98; --muted-2:#62656a;
  /* Accent — Linear signature indigo, with a purple+green for variety */
  --accent:#7170ff; --accent-2:#9b8afb; --accent-3:#4cb782;
  /* Borders — hairlines, not frames */
  --border:rgba(255,255,255,0.07); --border-2:rgba(255,255,255,0.12);
  --hairline:rgba(255,255,255,0.04);
  /* Status colors — calmer than the previous neon */
  --good:#4cb782; --warn:#e2a93f; --bad:#eb5757; --crit:#f25555;
  --code-bg:#1a1b1e;
  /* Shadows — barely there; structure comes from borders */
  --shadow-sm:0 1px 2px rgba(0,0,0,0.30);
  --shadow-md:0 8px 24px rgba(0,0,0,0.18),0 2px 4px rgba(0,0,0,0.16);
  --shadow-lg:0 16px 48px rgba(0,0,0,0.32),0 4px 12px rgba(0,0,0,0.20);
  --shadow-glow:0 0 0 1px rgba(113,112,255,0.45),0 0 16px rgba(113,112,255,0.18);
  /* Radii — Linear is precise, not rounded */
  --r-sm:4px; --r-md:6px; --r-lg:8px;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
}
*{box-sizing:border-box;}
html,body{margin:0;}
body{
  /* Flat near-black with a single subtle indigo wash from the top — the
     restrained Linear backdrop. No competing gradients from multiple
     directions; the eye should land on content, not chrome. */
  background:
    radial-gradient(1200px 500px at 50% -10%, rgba(113,112,255,0.06), transparent 60%),
    var(--bg);
  background-attachment:fixed;
  color:var(--text);
  font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  font-size:14px; line-height:1.55;
  font-feature-settings:"cv11","ss01","ss03";
  letter-spacing:-0.003em;
  -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
  letter-spacing:-0.005em;
}
::selection{background:rgba(113,112,255,0.32);color:#fff;}

/* ----- Header / Top bar ---------------------------------------------- */
.topbar{
  position:sticky; top:0; z-index:50;
  background:rgba(8,9,10,0.72);
  backdrop-filter:blur(16px) saturate(160%);
  -webkit-backdrop-filter:blur(16px) saturate(160%);
  border-bottom:1px solid var(--border);
}
.topbar-inner{
  margin:0; padding:12px 28px;
  display:flex; gap:24px; align-items:center; flex-wrap:wrap;
}
.brand{display:flex;align-items:center;gap:14px;font-weight:600;font-size:22px;letter-spacing:-0.018em;}
.brand .logo{
  width:64px; height:64px; border-radius:12px;
  display:flex; align-items:center; justify-content:center;
  position:relative; overflow:hidden;
  /* Reset default button chrome so the <button> wrapper looks
     identical to the previous <div>. */
  padding:0; cursor:pointer; outline:none;
  /* Soft radial wash that picks up Clanker's pink + the Linear indigo
     accent — gives the mascot a glow without being neon, and keeps the
     logo readable on the near-black topbar. */
  background:
    radial-gradient(circle at 35% 30%, rgba(244,114,182,0.18), transparent 65%),
    radial-gradient(circle at 70% 80%, rgba(113,112,255,0.16), transparent 65%),
    var(--panel-elev);
  border:1px solid var(--border-2);
  box-shadow:0 1px 2px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.06);
  transition:transform 0.22s cubic-bezier(0.2,0.8,0.2,1), border-color 0.18s;
}
.brand .logo:focus-visible{
  outline:2px solid var(--accent); outline-offset:2px;
}
.brand:hover .logo{
  transform:rotate(-4deg) scale(1.04);
  border-color:rgba(244,114,182,0.35);
}
/* Logo lightbox — click the topbar logo to see Clanker full-size.
   Backdrop blurs the page; image animates in with a small bounce.
   Click backdrop, ESC, or close button to dismiss. */
.logo-lightbox{
  position:fixed; inset:0; z-index:200; display:none;
  align-items:center; justify-content:center;
  background:rgba(8,9,10,0.78);
  backdrop-filter:blur(12px) saturate(140%);
  -webkit-backdrop-filter:blur(12px) saturate(140%);
  animation:lbFade 0.22s ease;
  cursor:zoom-out;
}
.logo-lightbox.open{display:flex;}
.logo-lightbox img{
  max-width:min(80vw, 720px);
  max-height:min(80vh, 720px);
  width:auto; height:auto;
  border-radius:24px;
  background:
    radial-gradient(circle at 35% 30%, rgba(244,114,182,0.20), transparent 65%),
    radial-gradient(circle at 70% 80%, rgba(113,112,255,0.18), transparent 65%),
    var(--panel-elev);
  border:1px solid var(--border-2);
  padding:24px;
  box-shadow:0 24px 64px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04);
  filter:drop-shadow(0 6px 16px rgba(0,0,0,0.5));
  animation:lbZoom 0.32s cubic-bezier(0.2,0.8,0.2,1);
  cursor:default;
}
.logo-lightbox-close{
  position:absolute; top:24px; right:24px;
  width:36px; height:36px; border-radius:50%;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--text); font-size:18px; cursor:pointer;
  display:flex; align-items:center; justify-content:center;
  transition:border-color 0.12s, background-color 0.12s;
}
.logo-lightbox-close:hover{
  background:var(--panel2); border-color:var(--border-2);
}
.logo-lightbox-caption{
  position:absolute; bottom:48px; left:50%; transform:translateX(-50%);
  color:var(--muted); font-size:13px; letter-spacing:-0.005em;
}
.logo-lightbox-caption strong{color:var(--text); font-weight:600;}
@keyframes lbFade{
  from{opacity:0;}
  to{opacity:1;}
}
@keyframes lbZoom{
  from{opacity:0; transform:scale(0.85) rotate(-3deg);}
  to{opacity:1; transform:scale(1) rotate(0);}
}
/* logo.png — Clanker the mascot. Drop-shadow lifts the pig-robot off
   the gradient panel; padding-3 keeps a touch of breathing room
   around the trotters. */
.brand .logo .logo-img{
  display:block; width:100%; height:100%;
  object-fit:contain; padding:3px;
  position:relative; z-index:1;
  filter:drop-shadow(0 2px 6px rgba(0,0,0,0.45));
}
.brand .logo svg{width:32px;height:32px;color:var(--accent);position:relative;z-index:1;}
.brand-text{display:flex;flex-direction:column;line-height:1.2;}
.brand-text > span:first-child{font-size:20px; font-weight:600; letter-spacing:-0.018em;}
.brand-tagline{
  font-size:11.5px; font-weight:400; color:var(--muted);
  letter-spacing:0.001em; margin-top:2px;
  max-width:520px;
}
/* Hide the tagline early — it eats ~250 px of the topbar and the same
   text reappears one row below in the welcome banner anyway. Removing
   it on laptops (≤1500 px) gets the topbar back under one row without
   the stats / search-bar overlap. */
@media (max-width: 1500px) {
  .brand-tagline{display:none;}
}

/* Welcome banner — always visible, never dismissable. Acts as the
   permanent positioning strapline + tour CTA right under the topbar. */
.first-visit-banner{
  display:flex;
  margin:0; padding:10px 28px;
  background:linear-gradient(180deg, rgba(113,112,255,0.08), rgba(113,112,255,0.03));
  border-bottom:1px solid rgba(113,112,255,0.20);
  font-size:13px; color:var(--text);
  align-items:center; gap:14px; flex-wrap:wrap;
}
.first-visit-banner b{color:var(--accent-2); font-weight:600;}
.first-visit-banner .banner-quote{
  font-style:italic; color:var(--text); font-weight:500;
  padding-right:14px; border-right:2px solid rgba(113,112,255,0.45);
  letter-spacing:-0.005em;
}
.first-visit-banner .banner-stats{
  color:var(--muted); font-family:var(--mono); font-size:11.5px;
}
@media (max-width: 760px) {
  .first-visit-banner .banner-quote{border-right:0; border-bottom:1px solid rgba(113,112,255,0.30); padding-right:0; padding-bottom:6px; width:100%;}
}
.first-visit-banner .banner-cta{
  margin-left:auto; display:inline-flex; align-items:center; gap:6px;
  color:var(--accent-2); font-weight:500; cursor:pointer;
  padding:5px 12px; border-radius:var(--r-sm);
  border:1px solid rgba(113,112,255,0.30);
  transition:all 0.15s; text-decoration:none;
}
.first-visit-banner .banner-cta:hover{
  background:rgba(113,112,255,0.12); border-color:rgba(113,112,255,0.55);
  color:var(--text);
}
@media (max-width: 760px) {
  .first-visit-banner{padding:10px 14px;}
  .first-visit-banner .banner-cta{margin-left:0; flex:1; justify-content:center;}
}

/* "What's new this week" banner. One-time per user; dismissal is
   persisted to localStorage under a versioned key so bumping the version
   re-triggers the banner for everyone. Sits below the first-visit row. */
.whatsnew-banner{
  position:relative;
  margin:0 auto 14px;
  padding:14px 44px 14px 18px;
  border:1px solid rgba(120,180,220,0.35);
  background:linear-gradient(180deg, rgba(60,100,150,0.20), rgba(40,60,100,0.10));
  border-radius:12px;
  color:var(--text);
  font-size:13px; line-height:1.55;
}
.whatsnew-banner .wn-head{
  display:flex; align-items:center; gap:10px;
  margin-bottom:10px;
}
.whatsnew-banner .wn-tag{
  font-size:10.5px; font-weight:700; letter-spacing:0.08em;
  text-transform:uppercase;
  padding:2px 8px; border-radius:99px;
  background:rgba(235,130,200,0.20); color:#f0a4cf;
  border:1px solid rgba(235,130,200,0.42);
}
.whatsnew-banner .wn-title{font-weight:600; color:var(--text);}
.whatsnew-banner .wn-close{
  position:absolute; top:8px; right:10px;
  background:transparent; border:none; color:var(--muted);
  font-size:20px; line-height:1; cursor:pointer; padding:4px 8px;
  border-radius:6px;
}
.whatsnew-banner .wn-close:hover{background:rgba(255,255,255,0.06); color:var(--text);}
.whatsnew-banner .wn-body{
  display:grid; grid-template-columns:1fr 1fr; gap:18px;
}
.whatsnew-banner .wn-col-head{
  font-size:11px; font-weight:600; letter-spacing:0.05em;
  text-transform:uppercase; color:var(--muted-2);
  margin-bottom:6px;
}
.whatsnew-banner .wn-list{
  margin:0; padding-left:18px;
}
.whatsnew-banner .wn-list li{margin-bottom:3px;}
.whatsnew-banner .wn-list b{color:var(--accent-2); font-weight:600;}
@media (max-width:780px){
  .whatsnew-banner .wn-body{grid-template-columns:1fr;}
}

/* All three stats bars share ONE centred slot — they overlap via
   absolute positioning inside .stats-wrap so the visible one always
   sits dead-centre regardless of which tab is active. Without this
   they'd be flex siblings each claiming 1/3 of the row width. */
.stats-wrap{
  flex:1; position:relative;
  display:flex; justify-content:center; align-items:center;
  min-height:64px;
  /* The stats children are position:absolute so they don't contribute
     to flex sizing — without a min-width here, the wrap can shrink to
     0 and the absolutely-positioned stats spill into the search bar
     on laptop widths (1280-1700 px). 460 px is wide enough for the
     widest stats variant (Articles: 5 columns × ~80 px). */
  min-width:460px;
}
.stats{
  position:absolute; left:50%; top:50%;
  transform:translate(-50%, -50%);
  display:flex; gap:16px; flex-wrap:nowrap;
  white-space:nowrap;
  /* Hidden by default — body class shows the active tab's bar. Same
     fade + slide animation; just no longer fighting siblings for space. */
  transition:opacity 0.25s ease, transform 0.3s cubic-bezier(0.2,0.8,0.2,1);
  opacity:0; pointer-events:none;
}
body.view-articles-active .stats-articles,
body.view-matrix-active   .stats-matrix,
body.view-intel-active    .stats-intel,
body.view-actors-active   .stats-actors,
body.view-library-active  .stats-library{
  opacity:1; transform:translate(-50%, -50%); pointer-events:auto;
}
/* Subtle entry animation — slide up from below as it fades in */
body:not(.view-articles-active) .stats-articles,
body:not(.view-matrix-active)   .stats-matrix,
body:not(.view-intel-active)    .stats-intel,
body:not(.view-actors-active)   .stats-actors,
body:not(.view-library-active)  .stats-library{
  transform:translate(-50%, calc(-50% + 8px));
}
@media(max-width:780px){
  .stats{ flex-wrap:wrap; white-space:normal; }
  .stats-wrap{ min-height:auto; }
}

/* ===== Mobile (≤780px) — proper responsive pass =====================
   Goals:
   1. Native-app-feel: bigger touch targets (44px+), smooth horizontal
      scroll on tab bars, sticky topbar with safe-area padding.
   2. Readable type — 15px body (not 12-13px), 1.55+ line-height.
   3. Generous vertical rhythm — 16-20px gaps between sections.
   4. Drawers slide up as full-screen sheets, not centered modals.
   5. Active/touched states (no hover on touch).
   6. Hide every desktop chrome that doesn't earn its place on phone. */
@media(max-width:780px){
  /* Use the device safe-area on iOS so content isn't behind the notch
     or the bottom home indicator. */
  body{
    padding-top:env(safe-area-inset-top);
    padding-left:env(safe-area-inset-left);
    padding-right:env(safe-area-inset-right);
  }
  /* === Topbar — two clean rows, brand top, scrollable tabs below === */
  .topbar{padding-top:env(safe-area-inset-top);}
  .topbar-inner{
    padding:10px 14px;
    flex-direction:column; align-items:stretch; gap:10px;
  }
  /* Row 1: brand + search */
  .brand{
    font-size:16px; gap:10px;
    width:100%;
  }
  .brand .logo{
    width:42px; height:42px; border-radius:10px;
    flex-shrink:0;
  }
  .brand-text > span:first-child{font-size:16px; letter-spacing:-0.014em;}
  .stats-wrap{display:none;}
  /* Search trigger — full-width on mobile so it reads as a real
     search input. With the TOC hidden, this becomes the primary way
     to skim 432 articles. */
  .search-trigger{
    width:100%; min-width:0; flex:1 1 auto;
    padding:10px 14px; font-size:14px;
    min-height:44px;
    border-radius:var(--r-md);
    margin-left:0;
  }
  .search-placeholder{
    display:inline; flex:1; min-width:0;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  }
  .search-shortcut{display:none;}
  /* Row 2: scrolling view-tab pill bar — feels native */
  .view-tabs{
    width:100%; max-width:100%;
    overflow-x:auto; overflow-y:hidden;
    -webkit-overflow-scrolling:touch;
    scrollbar-width:none;
    flex-wrap:nowrap; padding:4px;
    scroll-snap-type:x proximity;
  }
  .view-tabs::-webkit-scrollbar{display:none;}
  .view-tab{
    flex:0 0 auto;
    padding:9px 16px;            /* taller — proper touch target */
    font-size:13.5px;
    scroll-snap-align:center;
    min-height:36px;
  }

  /* === Articles main grid — single column, no TOC ===
     The desktop TOC is a 432-item nav rail — on mobile that means
     scrolling past every article title before reaching the first
     card. Hide it; rely on Ctrl+K search and the inline filters
     instead. */
  main, main.width-compact, main.width-wide, main.width-full{
    padding:12px;
    gap:0;
    /* minmax(0, 1fr) — NOT plain 1fr — so the column actually shrinks
       to fit the viewport. Plain 1fr defaults to min-content sizing,
       and our <pre> blocks (KQL queries with long single lines) have
       a min-content of ~4,400 px. That dragged the whole article view
       to 4,500+ px wide on mobile. */
    grid-template-columns:minmax(0, 1fr);
  }
  nav.toc{display:none;}

  /* Article cards — readable, scannable */
  article.card{
    padding:24px 18px 18px;
    font-size:14px; line-height:1.6;
    border-radius:var(--r-md);
  }
  article.card h2{
    font-size:18px; line-height:1.3;
    margin:14px 0 8px;
    letter-spacing:-0.014em;
  }
  article.card .pubmeta{
    font-size:11.5px; gap:8px; margin-bottom:12px;
    flex-wrap:wrap; color:var(--muted-2);
  }
  article.card .pubmeta span:not(:first-child)::before{margin-right:8px;}
  article.card p.summary{font-size:13.5px; line-height:1.55; margin:8px 0 12px;}
  article.card .sev-ribbon{left:18px; font-size:10px; padding:4px 11px;}
  article.card .source-badges{margin:4px 0;}
  article.card .source-badge{font-size:10.5px; padding:3px 8px;}
  /* Hint text below ATT&CK pills row eats vertical space — hide on mobile */
  article.card .ind-group + .btn-meta,
  article.card .meta-hint{display:none;}
  /* Action row — compact */
  article.card .action-row{gap:8px; margin:12px 0;}
  article.card .action-row .btn-meta{font-size:11px; line-height:1.4;}
  /* Inline UC details — tighter padding */
  article.card details.uc{margin-bottom:8px;}
  article.card details.uc summary{padding:10px 12px; font-size:13px;}
  article.card .uc-body{padding:0 12px 12px;}
  article.card .uc-meta{font-size:11.5px;}
  /* Action row buttons — bigger touch targets */
  .btn, .btn-kc{
    min-height:38px; padding:8px 14px; font-size:13px;
  }
  /* IOC indicator pills — slightly bigger, less cramped */
  .ind, .source-badge{min-height:22px; line-height:1.7;}

  /* === Info banner — friendlier defaults === */
  .info-banner summary{
    padding:14px 16px; font-size:13.5px;
    min-height:48px;
  }
  .info-banner .info-body{
    padding:0 16px 16px 44px; font-size:13.5px; line-height:1.65;
  }
  .info-banner .info-hint{display:none;}

  /* === Filter toolbars (articles + actors) ===
     On mobile we keep the labelled groups but each chip row scrolls
     horizontally instead of wrapping — that way 11 source chips +
     2 feature chips don't take 4 rows of vertical space. Snap to
     centre so a swipe lands cleanly. */
  .filter-toolbar, .actors-filters{
    padding:12px;
    border-radius:var(--r-md);
  }
  .filter-toolbar .ft-group, .actors-filters .ft-group{
    flex-direction:column; align-items:stretch; gap:6px;
    padding:4px 0;
  }
  .filter-toolbar .ft-group + .ft-group,
  .actors-filters .ft-group + .ft-group{
    padding-top:10px;
  }
  .filter-toolbar .ft-label, .actors-filters .ft-label{
    min-width:0; font-size:10.5px;
  }
  /* Chip row → single horizontal-scroll line on mobile */
  .filter-toolbar .ft-chips, .actors-filters .ft-chips{
    gap:6px;
    flex-wrap:nowrap;
    overflow-x:auto;
    overflow-y:hidden;
    -webkit-overflow-scrolling:touch;
    scrollbar-width:none;
    padding-bottom:4px;
    scroll-snap-type:x proximity;
  }
  .filter-toolbar .ft-chips::-webkit-scrollbar,
  .actors-filters .ft-chips::-webkit-scrollbar{display:none;}
  .src-chip, .actors-country-chip{
    flex:0 0 auto;
    padding:7px 11px; font-size:12px;
    min-height:34px;
    scroll-snap-align:start;
    white-space:nowrap;
  }
  .width-toggle{margin-left:0; align-self:flex-start;}
  .width-toggle button{padding:6px 12px; font-size:11px; min-height:32px;}

  /* === Threat Intel tab === */
  .intel-toolbar{flex-direction:column; align-items:stretch; gap:10px;}
  .intel-table-wrap{
    overflow-x:auto;
    -webkit-overflow-scrolling:touch;
    border-radius:var(--r-md);
  }

  /* === Threat Actors tab === */
  .actors-wrap{padding:14px;}
  .actors-hero{
    gap:0;
    padding:14px;
    border-radius:var(--r-md);
    /* 2-column stat grid instead of flex-wrap so the layout is tidy */
    display:grid; grid-template-columns:1fr 1fr;
    column-gap:14px; row-gap:12px;
  }
  .actors-hero .hero-stat .v{font-size:20px;}
  .actors-hero .hero-stat .l{font-size:10px; letter-spacing:0.05em;}
  .actors-toolbar{
    padding:12px 14px; gap:10px;
    flex-direction:column; align-items:stretch;
  }
  .actors-toolbar input{font-size:14px; padding:11px 14px; min-height:44px;}
  .actors-toolbar select{
    width:100%; font-size:14px; padding:11px 12px; min-height:44px;
  }
  .actors-grid{grid-template-columns:1fr; gap:12px;}
  .actor-card{
    padding:16px 18px; gap:12px;
    border-radius:var(--r-md);
  }
  .actor-card .ac-flag{font-size:28px;}
  .actor-card .ac-name{font-size:15.5px;}
  .actor-card .ac-country{font-size:11px;}
  .actor-card .ac-aliases{font-size:11.5px; line-height:1.5;}
  .actor-card .ac-stats .ac-stat .v{font-size:18px;}

  /* === Matrix tab === */
  .matrix-wrap{padding:12px;}
  .matrix-toolbar{
    flex-direction:column; align-items:stretch; gap:10px;
    padding:12px 14px;
  }
  #matrixSearch{
    width:100%; padding:11px 14px; font-size:14px; min-height:44px;
  }
  .matrix-mode button{padding:8px 12px; font-size:12px; min-height:38px;}
  .matrix-stats{font-size:11px; gap:12px; flex-wrap:wrap;}
  .matrix-legend{padding:10px 12px; font-size:11px;}
  .matrix-grid, .matrix{
    overflow-x:auto;
    -webkit-overflow-scrolling:touch;
  }

  /* === Workflow + About tab === */
  .workflow-wrap{padding:16px;}
  .wf-title{font-size:22px;}
  .wf-step, .wf-card{padding:16px 18px; font-size:13.5px; line-height:1.6;}
  .wf-card h3{font-size:16px;}
  .wf-table thead{display:none;}
  .wf-diagram{padding:10px;}

  /* === Drawers — feel like native bottom sheets === */
  .drawer-bg{backdrop-filter:none;}      /* perf on lower-end mobiles */
  .drawer{
    width:100vw; height:100vh; max-height:100vh;
    top:0; left:0; right:0; bottom:0;
    transform:none;
    border-radius:0;
    padding-top:env(safe-area-inset-top);
    padding-bottom:env(safe-area-inset-bottom);
  }
  .drawer-head{padding:16px 18px;}
  .drawer-head h3{font-size:18px; line-height:1.3;}
  .drawer-section{padding:0 16px; font-size:13.5px;}
  .drawer-section h4{font-size:13px;}
  .drawer-close{
    width:38px; height:38px; font-size:22px;
    top:12px; right:12px;
  }
  .actor-uc-row{flex-wrap:wrap; padding:11px 14px; min-height:44px;}
  .actor-uc-row .uc-techs{font-size:10.5px; flex-basis:100%;}
  .uc-card-row{padding:11px 14px; min-height:48px;}
  .ind.tech, .ind{font-size:11px; padding:3px 8px;}
  .art-jump{padding:11px 14px; min-height:44px;}

  /* === Lightbox === */
  .logo-lightbox img{
    max-width:88vw; max-height:72vh; padding:14px; border-radius:14px;
  }
  .logo-lightbox-close{top:14px; right:14px; width:40px; height:40px;}
  .logo-lightbox-caption{bottom:24px; font-size:12px;}

  /* === Touch-state polish — remove hover lifts, add active states === */
  article.card:hover{transform:none;}
  .actor-card:hover, .src-chip:hover, .view-tab:hover, .nav-item:hover,
  .actors-country-chip:hover{background:inherit;}
  .actor-card:active{background:var(--panel2);}
  .src-chip:active, .actors-country-chip:active{
    background:var(--panel2); border-color:var(--border-2);
  }
  .nav-item:active{background:var(--panel2);}
  .btn:active, .view-tab:active{background:var(--panel2);}

  /* === Footer + about copy === */
  .actors-footer p, .info-banner .info-body p{line-height:1.6;}
  footer{padding:18px 14px; font-size:12px;}
}

/* Very narrow phones (≤380px) — slim further so nothing overflows */
@media(max-width:380px){
  .topbar-inner{padding:9px 12px;}
  .brand .logo{width:38px; height:38px;}
  .brand-text > span:first-child{font-size:14.5px;}
  .view-tab{padding:8px 14px; font-size:13px;}
  article.card{padding:18px 14px;}
  article.card h2{font-size:18px;}
  .actors-hero{grid-template-columns:1fr 1fr; column-gap:10px;}
  .actors-hero .hero-stat .v{font-size:18px;}
  .actor-card{padding:14px 16px;}
}
/* Workflow tab: no stats bar — purposeful blank space, the diagram speaks */
.stat{
  display:flex; flex-direction:column; align-items:center;
  padding:6px 12px; min-width:64px;
}
.stat .v{font-size:18px;font-weight:600;color:var(--text);font-variant-numeric:tabular-nums;letter-spacing:-0.014em;}
.stat .l{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;font-weight:500;margin-top:2px;}

.search-trigger{
  display:flex; align-items:center; gap:10px;
  background:var(--panel); border:1px solid var(--border);
  padding:8px 14px; border-radius:var(--r-md);
  color:var(--muted); cursor:pointer; transition:all 0.15s;
  min-width:240px; font-family:inherit; font-size:13px;
}
.search-trigger:hover{border-color:var(--border-2);color:var(--text);}
.search-placeholder{flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}
.search-shortcut{display:inline-flex; gap:4px; flex-shrink:0; margin-left:14px;}
.search-trigger kbd{
  padding:2px 7px; font-size:10.5px; font-family:inherit; line-height:1;
  background:var(--panel2); border:1px solid var(--border-2); border-radius:4px;
  color:var(--muted); font-weight:600;
}

/* SOC Cheat Sheet button — opens cheatsheet.html in a new window. */
.cheatsheet-btn{
  display:inline-flex; align-items:center; gap:8px;
  padding:8px 14px; border-radius:var(--r-md);
  background:linear-gradient(180deg, rgba(113,112,255,0.14), rgba(113,112,255,0.06));
  border:1px solid rgba(113,112,255,0.30);
  color:var(--text); font-family:inherit; font-size:12.5px; font-weight:500;
  cursor:pointer; transition:all 0.15s; text-decoration:none; white-space:nowrap;
}
.cheatsheet-btn:hover{
  background:linear-gradient(180deg, rgba(113,112,255,0.22), rgba(113,112,255,0.10));
  border-color:rgba(113,112,255,0.55);
  box-shadow:0 0 0 3px rgba(113,112,255,0.10);
}
.cheatsheet-btn svg{stroke:var(--accent-2);flex-shrink:0;}

/* Tour replay button — quieter than the cheat-sheet CTA. */
.tour-trigger{
  display:inline-flex; align-items:center; gap:6px;
  padding:8px 12px; border-radius:var(--r-md);
  background:transparent; color:var(--muted);
  border:1px solid var(--border);
  font-family:inherit; font-size:12.5px; font-weight:500;
  cursor:pointer; transition:all 0.15s; white-space:nowrap;
}
.tour-trigger:hover{
  border-color:rgba(113,112,255,0.45);
  color:var(--text);
  background:rgba(113,112,255,0.06);
}
.tour-trigger svg{flex-shrink:0;}

/* =================================================================
   Detection Library — top-level view of every UC as a structured
   card, plus a slide-in detail drawer showing the full SOC-ready
   page (description, MITRE, queries, data sources, FPs, tuning,
   severity, SOC Value Score, recent attacks, blog sources).
   ================================================================= */
.lib-wrap{
  margin:0; padding:18px 28px 36px;
  display:flex; flex-direction:column; gap:18px;
}
@media (max-width: 980px){ .lib-wrap{padding:14px 18px 28px;} }
.lib-header{
  display:flex; flex-direction:column; gap:12px;
  background:linear-gradient(180deg, rgba(113,112,255,0.05), rgba(113,112,255,0.0));
  border:1px solid rgba(113,112,255,0.18);
  border-radius:var(--r-lg);
  padding:18px 20px;
}
.lib-title-row{display:flex; align-items:baseline; gap:14px; flex-wrap:wrap;}
.lib-title{
  margin:0; font-size:22px; font-weight:600; letter-spacing:-0.02em;
  color:var(--text);
}
.lib-subtitle{font-size:13px; color:var(--muted);}
.lib-toolbar{
  display:flex; align-items:center; gap:12px; flex-wrap:wrap;
}
.lib-toolbar input{
  flex:1; min-width:240px;
  padding:9px 14px; border-radius:var(--r-md);
  background:var(--panel); border:1px solid var(--border);
  color:var(--text); font:inherit; font-size:13.5px;
  transition:border-color 0.15s;
}
.lib-toolbar input:focus{outline:0; border-color:var(--accent);}
.lib-result-count{
  font-family:var(--mono); font-size:11.5px;
  color:var(--muted-2); letter-spacing:0.02em;
}
.lib-filter-row{display:flex; flex-wrap:wrap; gap:8px;}
.lib-filter-group{
  display:flex; align-items:center; gap:6px;
  padding:4px 10px 4px 4px;
  border:1px solid var(--border);
  background:var(--panel);
  border-radius:99px;
  font-size:12px;
}
.lib-filter-group .lf-label{
  background:rgba(113,112,255,0.12);
  color:var(--accent-2);
  font-weight:600; font-size:10.5px; letter-spacing:0.04em; text-transform:uppercase;
  padding:3px 9px; border-radius:99px;
  font-family:var(--mono);
}
.lib-filter-group select{
  background:transparent; color:var(--text); border:0;
  font:inherit; font-size:12.5px; padding:2px 4px;
  cursor:pointer; min-width:90px;
}
.lib-filter-group select:focus{outline:0;}
/* The OS-rendered popup that opens when you click a <select> doesn't inherit
   transparent backgrounds — Chrome/Edge on Windows show solid white by
   default, which renders the dark site text invisible. Force the option list
   to match the dark panel. */
.lib-filter-group select option,
#actorsSort option{
  background:#0d0e10;
  color:#e7e7eb;
}
.lib-pill-group{
  display:inline-flex; gap:2px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:99px; padding:2px;
}
.lib-pill{
  background:transparent; border:0; color:var(--muted);
  padding:5px 11px; border-radius:99px;
  font:inherit; font-size:11.5px; font-weight:500;
  cursor:pointer; transition:all 0.15s;
  font-family:var(--mono); letter-spacing:0.02em;
}
.lib-pill:hover{color:var(--text);}
.lib-pill.on{
  background:linear-gradient(180deg, rgba(113,112,255,0.30), rgba(113,112,255,0.18));
  color:var(--text);
  box-shadow:0 0 0 1px rgba(113,112,255,0.45) inset;
}
.lib-pill.platform-d.on{ background:linear-gradient(180deg, rgba(80,200,160,0.30), rgba(80,200,160,0.18)); box-shadow:0 0 0 1px rgba(80,200,160,0.55) inset; }
.lib-pill.platform-s.on{ background:linear-gradient(180deg, rgba(110,160,255,0.30), rgba(110,160,255,0.18)); box-shadow:0 0 0 1px rgba(110,160,255,0.55) inset; }
.lib-pill.platform-z.on{ background:linear-gradient(180deg, rgba(255,170,90,0.30), rgba(255,170,90,0.18)); box-shadow:0 0 0 1px rgba(255,170,90,0.55) inset; }
.lib-pill.platform-p.on{ background:linear-gradient(180deg, rgba(220,120,200,0.30), rgba(220,120,200,0.18)); box-shadow:0 0 0 1px rgba(220,120,200,0.55) inset; }
.lib-pill.platform-dd.on{ background:linear-gradient(180deg, rgba(120,90,200,0.32), rgba(120,90,200,0.18)); box-shadow:0 0 0 1px rgba(120,90,200,0.60) inset; }
/* Target-surface filter pills (windows / linux / aws / azure / ...). */
.lib-target-pills{flex-wrap:wrap; max-width:100%; gap:4px;}
.lib-pill.lib-target{padding:5px 9px;}
.lib-pill.lib-target .cnt{
  display:inline-block; min-width:18px; padding:0 5px; margin-left:5px;
  border-radius:99px; background:rgba(255,255,255,0.07);
  color:var(--muted); font-size:10.5px; font-weight:500;
}
.lib-pill.lib-target.on{
  background:linear-gradient(180deg, rgba(180,200,90,0.30), rgba(180,200,90,0.18));
  box-shadow:0 0 0 1px rgba(180,200,90,0.55) inset;
}
.lib-pill.lib-target.on .cnt{background:rgba(180,200,90,0.25); color:var(--text);}
/* Kind filter pills — Normal / LLM / WKC. Each gets a distinct accent so
   the analyst can spot at a glance which bucket they're filtering on.
   Hover-title (set inline in build) explains what's in each bucket. */
.lib-kind-pills{gap:4px;}
.lib-pill.lib-kind{padding:5px 10px; cursor:help;}
.lib-pill.lib-kind .cnt{
  display:inline-block; min-width:18px; padding:0 5px; margin-left:5px;
  border-radius:99px; background:rgba(255,255,255,0.07);
  color:var(--muted); font-size:10.5px; font-weight:500;
}
.lib-pill.lib-kind-normal.on{
  background:linear-gradient(180deg, rgba(120,180,220,0.30), rgba(120,180,220,0.18));
  box-shadow:0 0 0 1px rgba(120,180,220,0.55) inset;
}
.lib-pill.lib-kind-llm.on{
  background:linear-gradient(180deg, rgba(255,205,120,0.32), rgba(255,205,120,0.18));
  box-shadow:0 0 0 1px rgba(255,205,120,0.60) inset;
}
.lib-pill.lib-kind-wkc.on{
  background:linear-gradient(180deg, rgba(235,130,200,0.30), rgba(235,130,200,0.18));
  box-shadow:0 0 0 1px rgba(235,130,200,0.55) inset;
}
.lib-pill.lib-kind.on .cnt{background:rgba(255,255,255,0.18); color:var(--text);}
/* Per-card target-surface tags — small monochrome chips. */
.lib-tag.lib-tg{
  background:rgba(140,160,200,0.12); color:var(--muted);
  border:1px solid rgba(140,160,200,0.20);
  font-size:10px; padding:1px 6px;
}
.lib-clear-btn{
  background:transparent; border:1px solid var(--border-2); color:var(--muted);
  padding:5px 12px; border-radius:99px;
  font:inherit; font-size:11.5px; cursor:pointer;
  transition:all 0.15s;
}
.lib-clear-btn:hover{color:var(--bad); border-color:rgba(255,90,90,0.40);}
.lib-grid{
  display:grid;
  grid-template-columns:repeat(auto-fill, minmax(360px, 1fr));
  gap:14px;
}
.lib-card{
  background:linear-gradient(180deg, var(--panel-elev), var(--panel));
  border:1px solid var(--border);
  border-radius:var(--r-md);
  padding:14px 16px;
  cursor:pointer;
  transition:transform 0.15s, border-color 0.15s, box-shadow 0.15s;
  display:flex; flex-direction:column; gap:10px;
  position:relative; overflow:hidden;
}
.lib-card:hover{
  transform:translateY(-1px);
  border-color:rgba(113,112,255,0.45);
  box-shadow:0 6px 18px rgba(0,0,0,0.32), 0 0 0 1px rgba(113,112,255,0.12) inset;
}
.lib-card-head{display:flex; align-items:flex-start; gap:10px;}
.lib-card-name{
  flex:1; font-size:14.5px; font-weight:600; line-height:1.35;
  color:var(--text); letter-spacing:-0.005em;
}
.lib-card-id{
  font-family:var(--mono); font-size:10.5px; color:var(--muted-2);
  letter-spacing:0.04em; margin-top:3px;
}
.lib-card-desc{
  font-size:12.5px; line-height:1.5; color:var(--muted);
  display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical;
  overflow:hidden;
}
.lib-card-meta{display:flex; flex-wrap:wrap; gap:5px; align-items:center;}
.lib-tag{
  display:inline-flex; align-items:center; gap:4px;
  padding:2px 7px; border-radius:99px;
  font-family:var(--mono); font-size:10px; font-weight:600;
  letter-spacing:0.03em;
  background:rgba(113,112,255,0.10);
  border:1px solid rgba(113,112,255,0.22);
  color:var(--accent-2);
}
.lib-tag.tactic{background:rgba(95,182,255,0.10); border-color:rgba(95,182,255,0.22); color:#a8c5ff;}
.lib-tag.tier{background:rgba(180,141,255,0.10); border-color:rgba(180,141,255,0.22); color:#c5b1ff;}
.lib-tag.sev-crit{background:rgba(255,90,90,0.14); border-color:rgba(255,90,90,0.40); color:#ff8e8e;}
.lib-tag.sev-high{background:rgba(255,150,90,0.14); border-color:rgba(255,150,90,0.36); color:#ffba8a;}
.lib-tag.sev-med{background:rgba(255,200,90,0.14); border-color:rgba(255,200,90,0.36); color:#ffd98a;}
.lib-tag.sev-low{background:rgba(150,200,255,0.10); border-color:rgba(150,200,255,0.30); color:#a8d0ff;}
.lib-tag.platform-d{background:rgba(80,200,160,0.12); border-color:rgba(80,200,160,0.32); color:#9bdfc1;}
.lib-tag.platform-s{background:rgba(110,160,255,0.12); border-color:rgba(110,160,255,0.32); color:#a8c5ff;}
.lib-tag.platform-z{background:rgba(255,170,90,0.12); border-color:rgba(255,170,90,0.32); color:#ffc78a;}
.lib-tag.platform-p{background:rgba(220,120,200,0.12); border-color:rgba(220,120,200,0.32); color:#ecaad8;}
.lib-tag.platform-dd{background:rgba(120,90,200,0.14); border-color:rgba(120,90,200,0.36); color:#c5b0ff;}
.lib-card-footer{
  display:flex; align-items:center; gap:10px; justify-content:space-between;
  padding-top:8px; border-top:1px solid rgba(255,255,255,0.05);
}
.lib-svs{
  display:inline-flex; align-items:baseline; gap:6px;
  font-family:var(--mono); font-size:11px; color:var(--muted-2);
}
.lib-svs-num{
  font-size:18px; font-weight:700; letter-spacing:-0.02em;
  color:var(--text);
  background:linear-gradient(180deg, var(--accent-2), var(--accent));
  -webkit-background-clip:text; -webkit-text-fill-color:transparent;
  background-clip:text;
}
.lib-svs-track{
  flex:1; max-width:120px; height:4px; border-radius:99px;
  background:rgba(255,255,255,0.06); overflow:hidden;
}
.lib-svs-fill{
  height:100%;
  background:linear-gradient(90deg, var(--accent-3), var(--accent), var(--accent-2));
  border-radius:99px;
  transition:width 0.3s;
}
.lib-card-articles{
  font-family:var(--mono); font-size:10.5px; color:var(--muted-2);
}
.lib-drawer{
  position:fixed; inset:0;
  z-index:8500;
  background:rgba(8,9,10,0.58);
  display:flex; align-items:stretch; justify-content:flex-end;
  opacity:0; transition:opacity 0.22s ease-out;
  pointer-events:none;
}
.lib-drawer.open{opacity:1; pointer-events:auto;}
.lib-drawer[hidden]{display:none;}
.lib-drawer-inner{
  width:min(880px, 100vw);
  height:100vh; overflow-y:auto;
  background:var(--bg);
  border-left:1px solid rgba(113,112,255,0.30);
  box-shadow:-24px 0 48px rgba(0,0,0,0.55);
  transform:translateX(40px);
  transition:transform 0.32s cubic-bezier(0.2,0.8,0.2,1.0);
  position:relative;
}
.lib-drawer.open .lib-drawer-inner{transform:translateX(0);}
.lib-drawer-close{
  position:sticky; top:14px; left:auto; float:right;
  margin:14px 14px 0 0; z-index:10;
  background:rgba(255,255,255,0.06); color:var(--muted);
  border:1px solid var(--border-2);
  width:32px; height:32px; border-radius:50%;
  font-size:20px; line-height:1; cursor:pointer;
  display:inline-flex; align-items:center; justify-content:center;
  transition:all 0.15s;
}
.lib-drawer-close:hover{color:var(--text); background:rgba(255,255,255,0.12); border-color:var(--accent-2);}
.lib-drawer-content{padding:24px 28px 56px;}
@media (max-width: 640px){ .lib-drawer-content{padding:16px 18px 36px;} }
.lib-detail-head{
  display:flex; flex-direction:column; gap:10px;
  margin-bottom:18px; padding-bottom:18px;
  border-bottom:1px solid var(--border);
}
.lib-detail-name{
  font-family:var(--mono); font-size:11px; letter-spacing:0.06em;
  color:var(--accent-2); text-transform:uppercase;
}
.lib-detail-title{
  margin:0; font-size:24px; font-weight:600; line-height:1.25;
  letter-spacing:-0.02em; color:var(--text);
}
.lib-detail-meta{display:flex; flex-wrap:wrap; gap:6px; align-items:center;}
.lib-detail-svs{
  margin-top:8px; display:flex; align-items:center; gap:14px;
  padding:14px 16px; border-radius:var(--r-md);
  background:linear-gradient(135deg, rgba(113,112,255,0.10), rgba(95,182,255,0.06));
  border:1px solid rgba(113,112,255,0.30);
}
.lib-detail-svs-score{display:flex; flex-direction:column; gap:2px; min-width:88px;}
.lib-detail-svs-num{
  font-size:32px; font-weight:700; line-height:1;
  background:linear-gradient(180deg, var(--accent-2), var(--accent));
  -webkit-background-clip:text; -webkit-text-fill-color:transparent;
  background-clip:text; letter-spacing:-0.03em;
}
.lib-detail-svs-label{
  font-family:var(--mono); font-size:10.5px; color:var(--muted-2);
  letter-spacing:0.04em; text-transform:uppercase;
}
.lib-detail-svs-grid{flex:1; display:grid; grid-template-columns:repeat(4, 1fr); gap:10px;}
.lib-svs-component{display:flex; flex-direction:column; gap:4px;}
.lib-svs-component-label{
  font-family:var(--mono); font-size:10px; color:var(--muted-2);
  letter-spacing:0.04em; text-transform:uppercase;
}
.lib-svs-component-bar{
  height:6px; border-radius:99px;
  background:rgba(255,255,255,0.06); overflow:hidden;
  position:relative;
}
.lib-svs-component-fill{height:100%; border-radius:99px; background:linear-gradient(90deg, var(--accent-3), var(--accent));}
.lib-svs-component-val{font-family:var(--mono); font-size:11px; font-weight:600; color:var(--text); letter-spacing:0.02em;}
.lib-section{margin:22px 0; display:flex; flex-direction:column; gap:8px;}
.lib-section-h{
  font-family:var(--mono); font-size:11px; letter-spacing:0.06em;
  color:var(--accent-2); text-transform:uppercase; font-weight:600;
  margin:0; display:flex; align-items:center; gap:8px;
}
.lib-section-h::before{
  content:''; width:4px; height:14px; border-radius:2px;
  background:linear-gradient(180deg, var(--accent), var(--accent-2));
}
.lib-section p{margin:0; font-size:13.5px; line-height:1.6; color:var(--text);}
.lib-section-body{
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:var(--r-md);
  padding:14px 16px;
  font-size:13px; line-height:1.6; color:var(--text);
}
.lib-section-body ul{margin:0; padding-left:18px;}
.lib-section-body li{margin:4px 0;}
.lib-mitre-grid{display:flex; flex-wrap:wrap; gap:8px;}
.lib-mitre-pill{
  display:inline-flex; flex-direction:column; gap:2px;
  padding:6px 12px; border-radius:var(--r-sm);
  background:var(--panel); border:1px solid rgba(95,182,255,0.30);
  text-decoration:none; color:inherit; cursor:pointer;
  transition:border-color 0.15s, background 0.15s;
}
.lib-mitre-pill:hover{border-color:rgba(95,182,255,0.60); background:rgba(95,182,255,0.06);}
.lib-mitre-pill .mp-tid{font-family:var(--mono); font-size:11.5px; font-weight:600; color:var(--accent-3); letter-spacing:0.02em;}
.lib-mitre-pill .mp-name{font-size:12px; color:var(--text);}
.lib-mitre-pill .mp-tactic{font-family:var(--mono); font-size:9.5px; color:var(--muted-2); letter-spacing:0.04em;}
.lib-query-tabs{display:flex; gap:2px; background:var(--panel); border:1px solid var(--border); border-radius:var(--r-sm); padding:2px; width:fit-content;}
.lib-query-tab{
  background:transparent; border:0; color:var(--muted);
  padding:6px 14px; border-radius:calc(var(--r-sm) - 2px);
  font:inherit; font-size:11.5px; font-weight:500;
  cursor:pointer; transition:all 0.15s;
}
.lib-query-tab:hover{color:var(--text);}
.lib-query-tab.on{background:var(--panel2); color:var(--text); box-shadow:0 0 0 1px rgba(113,112,255,0.30);}
.lib-query-pre{
  margin:0; padding:14px 16px;
  background:#0c0d10; border:1px solid var(--border);
  border-radius:var(--r-md);
  font-family:var(--mono); font-size:12px; line-height:1.55;
  color:#e3e3eb; overflow:auto; max-height:380px;
  white-space:pre; tab-size:2;
}
.lib-query-toolbar{display:flex; align-items:center; gap:10px; justify-content:space-between;}
.lib-query-meta{font-family:var(--mono); font-size:10.5px; color:var(--muted-2);}
.lib-copy-btn{
  background:transparent; border:1px solid var(--border-2);
  color:var(--muted); font:inherit; font-size:11px; font-weight:500;
  padding:4px 10px; border-radius:var(--r-sm); cursor:pointer;
  transition:all 0.15s;
}
.lib-copy-btn:hover{color:var(--text); border-color:var(--accent-2);}
.lib-copy-btn.copied{color:#9bdfc1; border-color:rgba(80,200,160,0.55);}
.lib-source-list{display:flex; flex-direction:column; gap:6px;}
.lib-source-row{
  display:flex; align-items:center; gap:10px;
  padding:8px 12px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-sm);
  text-decoration:none; color:inherit;
  transition:border-color 0.15s, background 0.15s;
}
.lib-source-row:hover{border-color:rgba(113,112,255,0.45); background:rgba(113,112,255,0.04);}
.lib-source-row .ls-sev{
  font-family:var(--mono); font-size:9.5px; font-weight:600;
  letter-spacing:0.04em; padding:2px 6px; border-radius:99px;
  text-transform:uppercase; flex-shrink:0;
}
.lib-source-row .ls-sev.crit{background:rgba(255,90,90,0.14); color:#ff8e8e; border:1px solid rgba(255,90,90,0.36);}
.lib-source-row .ls-sev.high{background:rgba(255,150,90,0.14); color:#ffba8a; border:1px solid rgba(255,150,90,0.36);}
.lib-source-row .ls-sev.med{background:rgba(255,200,90,0.14); color:#ffd98a; border:1px solid rgba(255,200,90,0.36);}
.lib-source-row .ls-sev.low{background:rgba(150,200,255,0.10); color:#a8d0ff; border:1px solid rgba(150,200,255,0.30);}
.lib-source-row .ls-title{flex:1; font-size:12.5px; color:var(--text); line-height:1.4;}
.lib-source-row .ls-src{
  font-family:var(--mono); font-size:10px; color:var(--muted-2);
  letter-spacing:0.04em; text-transform:uppercase; flex-shrink:0;
}
.lib-empty{
  padding:48px 28px; text-align:center;
  color:var(--muted); font-size:14px;
  background:var(--panel); border:1px dashed var(--border-2);
  border-radius:var(--r-md);
}
.lib-empty b{color:var(--text);}

/* =================================================================
   Guided tour — full-page overlay, spotlight, floating card.
   ================================================================= */
.tour-overlay{
  position:fixed; inset:0;
  background:rgba(8,9,10,0.45);
  z-index:9000;
  opacity:0; pointer-events:none;
  transition:opacity 0.22s ease-out;
}
body.tour-on .tour-overlay{opacity:1; pointer-events:auto;}

/* Box-shadow spotlight: a 9999px outer-spread shadow on the target
   element creates the "punch hole" effect. The element appears to
   float above the dimmed page. No DOM gymnastics needed. Lower
   outer-dim opacity keeps surrounding features readable so the user
   sees what's actually being demoed. */
.tour-spotlight{
  position:relative !important;
  z-index:9050 !important;
  box-shadow:
    0 0 0 3px rgba(113,112,255,0.75),
    0 0 0 8px rgba(113,112,255,0.22),
    0 0 0 9999px rgba(8,9,10,0.55) !important;
  border-radius:var(--r-md);
  transition:box-shadow 0.3s ease-out;
  animation:tour-pulse 2.4s ease-in-out infinite;
}
@keyframes tour-pulse{
  0%, 100% { box-shadow:
    0 0 0 3px rgba(113,112,255,0.75),
    0 0 0 8px rgba(113,112,255,0.22),
    0 0 0 9999px rgba(8,9,10,0.55) !important; }
  50% { box-shadow:
    0 0 0 3px rgba(113,112,255,1.00),
    0 0 0 13px rgba(113,112,255,0.14),
    0 0 0 9999px rgba(8,9,10,0.55) !important; }
}
/* Block clicks on everything except the spotlight + tour card while
   tour is on. Lets the user navigate the tour without accidentally
   clicking through to the underlying view. */
/* No overflow:hidden — the engine relies on scrollIntoView to bring
   off-screen targets (actor cards, library cards) into view. The dim
   is position:fixed so it stays glued to the viewport regardless of
   scroll, and pointer-events:none on the .view blocks accidental
   underlying clicks. */
body.tour-on .topbar,
body.tour-on .view{pointer-events:none;}
body.tour-on .tour-spotlight,
body.tour-on .tour-spotlight *,
body.tour-on .tour-card,
body.tour-on .tour-card *{pointer-events:auto;}

/* Floating tour card. Default anchor is bottom-center; the engine
   flips it to top-center via .tour-card-top when the spotlight is in
   the lower half of the viewport, so the card never overlaps the
   element it's narrating. */
.tour-card{
  position:fixed; left:50%; bottom:32px; top:auto;
  transform:translateX(-50%) translateY(8px);
  width:min(440px, calc(100vw - 32px));
  background:linear-gradient(180deg, var(--panel-elev), var(--panel));
  border:1px solid rgba(113,112,255,0.40);
  border-radius:var(--r-lg);
  padding:18px 20px 14px;
  box-shadow:
    0 24px 48px rgba(0,0,0,0.40),
    0 4px 12px rgba(0,0,0,0.32),
    0 0 0 1px rgba(255,255,255,0.04) inset;
  z-index:9100;
  opacity:0;
  transition:transform 0.28s cubic-bezier(0.2,0.8,0.2,1.0),
             opacity 0.22s ease-out,
             top 0.28s cubic-bezier(0.2,0.8,0.2,1.0),
             bottom 0.28s cubic-bezier(0.2,0.8,0.2,1.0);
}
.tour-card.tour-card-top{
  top:24px; bottom:auto;
  transform:translateX(-50%) translateY(-8px);
}
body.tour-on .tour-card{
  opacity:1;
  transform:translateX(-50%) translateY(0);
}
body.tour-on .tour-card.tour-card-top{
  transform:translateX(-50%) translateY(0);
}
.tour-card[hidden]{display:none;}

/* Preview chips — small visual showcase row below the body text,
   used to render concrete examples of what the spotlight is about
   (e.g. a row of platform pills, a fake search-bar mock, etc). */
.tour-preview{
  margin:0 0 14px;
  display:flex; flex-wrap:wrap; gap:6px;
  padding:10px 12px;
  background:rgba(113,112,255,0.06);
  border:1px solid rgba(113,112,255,0.18);
  border-radius:var(--r-md);
  align-items:center;
}
.tour-preview:empty{display:none;}
.tour-preview-pill{
  display:inline-flex; align-items:center; gap:5px;
  padding:3px 9px; border-radius:99px;
  font-family:var(--mono); font-size:10.5px; font-weight:600;
  letter-spacing:0.02em;
  background:rgba(113,112,255,0.14);
  border:1px solid rgba(113,112,255,0.32);
  color:var(--accent-2);
}
.tour-preview-pill.platform-d{ background:rgba(80,200,160,0.12); border-color:rgba(80,200,160,0.32); color:#9bdfc1; }
.tour-preview-pill.platform-s{ background:rgba(110,160,255,0.12); border-color:rgba(110,160,255,0.32); color:#a8c5ff; }
.tour-preview-pill.platform-z{ background:rgba(255,170,90,0.12); border-color:rgba(255,170,90,0.32); color:#ffc78a; }
.tour-preview-pill.platform-p{ background:rgba(220,120,200,0.12); border-color:rgba(220,120,200,0.32); color:#ecaad8; }
.tour-preview-pill.platform-dd{ background:rgba(120,90,200,0.14); border-color:rgba(120,90,200,0.36); color:#c5b0ff; }
.tour-preview-key{
  font-family:var(--mono); font-size:11px; font-weight:600;
  padding:3px 7px; border-radius:4px;
  background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.14);
  color:var(--text);
}
.tour-preview-meta{
  font-family:var(--mono); font-size:10.5px; color:var(--muted-2);
  letter-spacing:0.02em;
}
.tour-card-header{
  display:flex; align-items:center; gap:10px;
  margin-bottom:6px;
}
.tour-section{
  font-family:var(--mono); font-size:10.5px; font-weight:600;
  letter-spacing:0.05em; text-transform:uppercase;
  color:var(--accent-2);
  padding:2px 8px; border-radius:99px;
  background:rgba(113,112,255,0.12);
  border:1px solid rgba(113,112,255,0.30);
}
.tour-counter{
  font-family:var(--mono); font-size:10.5px;
  color:var(--muted-2); margin-left:auto;
}
.tour-skip{
  background:transparent; border:0; color:var(--muted);
  font:inherit; font-size:11.5px; cursor:pointer;
  padding:2px 4px; border-radius:var(--r-sm);
  transition:color 0.15s;
}
.tour-skip:hover{color:var(--bad);}
.tour-title{
  margin:0 0 6px;
  font-size:16px; font-weight:600; letter-spacing:-0.018em;
  color:var(--text);
}
.tour-body{
  margin:0 0 14px;
  font-size:13px; line-height:1.55;
  color:var(--muted);
}
.tour-body b{color:var(--text); font-weight:500;}
.tour-progress{
  display:flex; gap:5px; justify-content:center;
  margin:0 0 14px;
}
.tour-progress span{
  width:6px; height:6px; border-radius:99px;
  background:rgba(255,255,255,0.10);
  transition:all 0.2s;
}
.tour-progress span.done{background:rgba(113,112,255,0.50);}
.tour-progress span.active{
  background:var(--accent);
  width:18px;
  box-shadow:0 0 8px rgba(113,112,255,0.55);
}
.tour-actions{
  display:flex; gap:8px;
}
.tour-btn{
  flex:1;
  padding:8px 14px; border-radius:var(--r-sm);
  font:inherit; font-size:12.5px; font-weight:500;
  cursor:pointer; transition:all 0.15s;
}
.tour-btn.tour-back{
  background:transparent; color:var(--muted);
  border:1px solid var(--border-2);
}
.tour-btn.tour-back:hover:not(:disabled){
  color:var(--text); border-color:var(--accent-2);
}
.tour-btn.tour-back:disabled{
  opacity:0.35; cursor:not-allowed;
}
.tour-btn.tour-next{
  background:linear-gradient(180deg, var(--accent), #5e5dd4);
  color:#fff; border:1px solid rgba(113,112,255,0.65);
  box-shadow:0 1px 0 rgba(255,255,255,0.10) inset, 0 2px 4px rgba(94,93,212,0.35);
}
.tour-btn.tour-next:hover{
  background:linear-gradient(180deg, #8281ff, var(--accent));
}
.tour-hint{
  margin:10px 0 0; padding:0;
  text-align:center; font-size:10.5px;
  color:var(--muted-2); font-family:var(--mono);
  letter-spacing:0.02em;
}
@media (max-width: 640px){
  .tour-card{
    bottom:14px; padding:14px 16px 12px;
    width:calc(100vw - 24px);
  }
  .tour-card.tour-card-top{top:14px;}
  .tour-spotlight{animation:none;}
}

/* ----- Filter bar ---------------------------------------------------- */
.filter-row{
  margin:0; padding:14px 28px 0;
  display:flex; gap:8px; flex-wrap:wrap; align-items:center;
}
.filter-label{font-size:11px; color:var(--muted); text-transform:uppercase;
  letter-spacing:0.08em; margin-right:6px; font-weight:600;}
.fchip{
  background:var(--panel); border:1px solid var(--border);
  padding:5px 12px; border-radius:999px; font-size:12px; cursor:pointer;
  color:var(--muted); transition:all 0.15s; font-family:inherit;
  display:inline-flex; align-items:center; gap:6px;
}
.fchip:hover{color:var(--text);border-color:var(--border-2);}
.fchip.on{
  color:var(--text); border-color:transparent;
  background:linear-gradient(135deg, rgba(95,182,255,0.25), rgba(180,141,255,0.18));
  box-shadow:0 0 0 1px rgba(95,182,255,0.4) inset;
}
.fchip .x{display:none;font-size:14px;line-height:1;opacity:0.6;}
.fchip.on .x{display:inline;}
.fchip .dot{width:6px;height:6px;border-radius:50%;background:var(--muted);}
.fchip.on .dot{background:var(--accent);}

/* ----- Main layout --------------------------------------------------- */
/* Width-mode is user-selectable via the toolbar in #articles. Default is
   "wide" so the article column uses most of the viewport on large monitors
   without sprawling on ultrawides. localStorage key: usecaseintel:width. */
main{
  margin:0; padding:18px 28px 28px;
  display:grid; gap:20px;
}
main.width-compact{grid-template-columns:260px minmax(0, 1180px);}
main.width-wide   {grid-template-columns:260px minmax(0, 1700px);}
main.width-full   {grid-template-columns:260px minmax(0, 1fr);}
main:not(.width-compact):not(.width-wide):not(.width-full){
  /* fallback if JS hasn't applied a class yet */
  grid-template-columns:260px minmax(0, 1700px);
}
@media(max-width:1280px){
  main, main.width-compact, main.width-wide, main.width-full{
    grid-template-columns:240px minmax(0, 1fr); gap:16px;
  }
}
@media(max-width:980px){
  main, main.width-compact, main.width-wide, main.width-full{
    /* minmax(0, 1fr) so unwrappable <pre> KQL doesn't push the column
       past the viewport. */
    grid-template-columns:minmax(0, 1fr); padding:18px;
  }
}

/* Width toolbar — matches view-tab segmented style */
.width-toggle{
  display:inline-flex; gap:2px; margin-left:auto;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); padding:2px;
}
.width-toggle button{
  background:transparent; border:0; color:var(--muted);
  padding:4px 10px; border-radius:calc(var(--r-md) - 2px);
  font-size:10.5px; font-family:inherit; font-weight:500;
  text-transform:uppercase; letter-spacing:0.05em;
  cursor:pointer; transition:color 0.12s, background-color 0.12s;
}
.width-toggle button:hover{color:var(--text); background:rgba(255,255,255,0.03);}
.width-toggle button.on{
  background:var(--panel-elev); color:var(--text);
  box-shadow:inset 0 0 0 1px var(--border);
}

nav.toc{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--r-lg);
  padding:10px; position:sticky; top:90px; max-height:calc(100vh - 110px);
  overflow:auto; box-shadow:var(--shadow-sm);
}
nav.toc::-webkit-scrollbar{width:6px;}
nav.toc::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:3px;}
nav.toc h3{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:0.08em;
  margin:6px 10px 8px;font-weight:600;}
.nav-item{
  display:flex; gap:10px; padding:9px 10px; border-radius:var(--r-md);
  color:var(--text); text-decoration:none; font-size:12.5px; line-height:1.35;
  margin-bottom:2px; align-items:flex-start; cursor:pointer;
  transition:all 0.12s ease;
  position:relative;
}
.nav-item:hover{background:var(--panel-elev);}
.nav-item.active{
  background:var(--panel2);
  box-shadow:inset 2px 0 0 var(--accent);
}
.nav-item .num{
  flex:0 0 24px; font-variant-numeric:tabular-nums; color:var(--muted);
  font-weight:600; font-size:11px;
}
.nav-item .ttl{flex:1;}
.nav-item .sev{
  flex:0 0 6px; height:6px; border-radius:50%; margin-top:7px;
  background:var(--good);
}
.nav-item .sev.med{background:var(--warn);}
.nav-item .sev.high{background:var(--bad);}
.nav-item .sev.crit{background:var(--crit);}

/* ----- Source filter bar (Articles tab) ------------------------------ */
/* ----- Article toolbar — labelled, multi-group filter surface --------
   Designed to stay legible as we add more filter groups over time.
   Layout: a single panel with a thin top accent, broken into
   labelled groups (Source / Content / Layout). Each group is a
   row of chips with its own muted-uppercase label. Groups wrap
   onto multiple lines on narrow viewports. */
.filter-toolbar{
  display:flex; flex-direction:column; gap:8px;
  padding:14px 16px; margin-bottom:12px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-lg);
  box-shadow:var(--shadow-sm);
}
.filter-toolbar .ft-group{
  display:flex; align-items:center; gap:10px;
  padding:4px 0;
  flex-wrap:wrap;
}
.filter-toolbar .ft-group + .ft-group{
  border-top:1px dashed var(--hairline);
  padding-top:10px;
}
.filter-toolbar .ft-label{
  flex:0 0 auto; min-width:62px;
  color:var(--muted-2); font-size:10.5px;
  font-weight:600; letter-spacing:0.08em;
  text-transform:uppercase;
  font-feature-settings:"cv11","ss01";
}
.filter-toolbar .ft-chips{
  display:flex; gap:6px; flex-wrap:wrap; align-items:center;
  flex:1 1 auto;
}
/* Layout group's width-toggle keeps its own segmented styling — just
   needs to slot into the .ft-chips container without the chip border. */
.filter-toolbar .ft-view .width-toggle{margin-left:0;}

/* Feature filter chips ("Has UCs", "LLM UCs only") — same chip-pill
   style as source chips but accent-coloured stripe on active so
   they read as a different filter axis. */
.src-chip.feat-chip.active{
  box-shadow:inset 2px 0 0 var(--accent);
  background:rgba(113,112,255,0.08);
  border-color:var(--border-2); color:var(--text);
}
/* Hide the legacy lg-label inside ft-chips (the All chip generator
   used to emit one); the ft-label above the row replaces it. */
.filter-toolbar .ft-chips .lg-label{display:none;}
/* LLM-UC info banner — collapsed details/summary that explains what
   an [LLM] prefix means before the analyst sees the filter. */
.info-banner{
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); margin-bottom:10px;
  font-size:13px;
}
.info-banner summary{
  display:flex; align-items:center; gap:10px;
  padding:10px 14px; cursor:pointer; list-style:none;
  color:var(--text); user-select:none;
  transition:background-color 0.12s;
}
.info-banner summary::-webkit-details-marker{display:none;}
.info-banner summary::before{
  content:"›"; color:var(--muted); font-size:16px; line-height:1;
  margin-right:2px; transition:transform 0.18s; display:inline-block;
}
.info-banner[open] summary::before{transform:rotate(90deg);}
.info-banner summary:hover{background:var(--panel-elev);}
.info-banner .info-icon{
  display:inline-flex; align-items:center; justify-content:center;
  width:20px; height:20px; border-radius:50%;
  background:rgba(113,112,255,0.15); color:var(--accent);
  font-size:11px; font-weight:600; flex-shrink:0;
}
.info-banner .info-hint{
  margin-left:auto; color:var(--muted-2); font-size:11.5px;
  font-style:italic;
}
.info-banner[open] .info-hint{display:none;}
.info-banner .info-body{
  padding:0 18px 14px 44px;
  line-height:1.6; color:var(--muted);
}
.info-banner .info-body p{margin:8px 0;}
.info-banner .info-body p:first-child{margin-top:0;}
.info-banner .info-body p:last-child{margin-bottom:0;}
.info-banner .info-body code{
  background:var(--panel-elev); padding:1px 5px; border-radius:3px;
  font-size:12px; color:var(--accent-3); font-family:var(--mono);
}
.info-banner .info-body strong{color:var(--text);}
.src-filter-bar .lg-label{flex:0 0 auto; min-width:72px;}
/* Source filter chips — Linear style. All chips share the same neutral
   panel + hairline; the only difference between sources is a 2px coloured
   left border in the active state. No saturated bg fills.  */
.src-chip{
  padding:5px 11px; border-radius:var(--r-md);
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:12px;
  font-weight:500; letter-spacing:-0.003em;
  transition:color 0.12s, border-color 0.12s, background-color 0.12s;
  display:inline-flex; align-items:center; gap:6px;
}
.src-chip:hover{color:var(--text); border-color:var(--border-2);}
.src-chip.active{
  color:var(--text); background:var(--panel2);
  border-color:var(--border-2);
  box-shadow:inset 2px 0 0 var(--accent);
}
/* Per-source active accent — a 2px coloured stripe on the left. */
.src-chip.active.thn{box-shadow:inset 2px 0 0 #7170ff;}
.src-chip.active.bc{box-shadow:inset 2px 0 0 #eb5757;}
.src-chip.active.ms{box-shadow:inset 2px 0 0 #9b8afb;}
.src-chip.active.kev{box-shadow:inset 2px 0 0 #e2a93f;}
.src-chip.active.talos{box-shadow:inset 2px 0 0 #4cb782;}
.src-chip.active.securelist{box-shadow:inset 2px 0 0 #4cb782;}
.src-chip.active.sentinel{box-shadow:inset 2px 0 0 #9b8afb;}
.src-chip.active.unit42{box-shadow:inset 2px 0 0 #e2a93f;}
.src-chip.active.eset{box-shadow:inset 2px 0 0 #7170ff;}
.src-chip.active.lab52{box-shadow:inset 2px 0 0 #4cb782;}
.src-chip.active.csn{box-shadow:inset 2px 0 0 #f25555;}
.src-chip .cnt{
  font-variant-numeric:tabular-nums; color:var(--muted-2);
  font-size:10.5px; font-weight:500;
}
article.card.src-hidden{display:none;}

/* ----- Article cards -------------------------------------------------
   Linear card: flat panel bg, hairline border, no gradient, no
   transform on hover. Hover lifts only the border + a subtle inner
   highlight — that's the look that makes the matrix and articles feel
   refined rather than vibe-coded. */
section#articles{display:flex; flex-direction:column; gap:18px;}
article.card{
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:var(--r-lg);
  padding:24px 26px;
  font-size:14px; line-height:1.6;
  position:relative;
  /* Sticky header is ~90-110px tall (brand row + tabs row). Without this,
     anchor jumps from the sidebar TOC scroll the article's top under the
     header and crop the title / severity ribbon. */
  scroll-margin-top:120px;
  transition:border-color 0.15s ease, background-color 0.15s ease;
  /* Skip layout + paint for offscreen articles. With ~590 cards in the
     Articles view, naive rendering blocks first paint for ~14s. The browser
     will re-render each card lazily as it scrolls into view. The
     contain-intrinsic-size keeps the scrollbar honest before measurement. */
  content-visibility:auto;
  contain-intrinsic-size:auto 720px;
}
article.card:hover{
  border-color:var(--border-2);
  background:var(--panel-elev);
}
article.card.hidden{display:none;}
article.card .sev-ribbon{
  position:absolute; top:0; left:24px; padding:3px 10px 4px;
  font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:0.08em;
  border-radius:0 0 6px 6px;
  background:rgba(76,183,130,0.16); color:var(--good);
  border:1px solid rgba(76,183,130,0.28); border-top:none;
}
article.card .sev-ribbon.med{background:rgba(226,169,63,0.14); color:var(--warn); border-color:rgba(226,169,63,0.30);}
article.card .sev-ribbon.high{background:rgba(235,87,87,0.14); color:var(--bad); border-color:rgba(235,87,87,0.30);}
article.card .sev-ribbon.crit{
  background:rgba(242,85,85,0.18); color:var(--crit);
  border-color:rgba(242,85,85,0.36);
}
article.card h2{margin:14px 0 8px 0;font-size:20px;line-height:1.25;letter-spacing:-0.018em;font-weight:600;}
article.card h2 a{color:var(--text);text-decoration:none;
  transition:color 0.12s ease;}
article.card h2 a:hover{color:var(--accent);}
article.card .pubmeta{color:var(--muted);font-size:12px;margin-bottom:14px;display:flex;gap:12px;flex-wrap:wrap;}
article.card .pubmeta span:not(:first-child)::before{content:"·";margin-right:12px;color:var(--muted-2);}
article.card p.summary{color:var(--muted);margin:8px 0 16px 0;font-size:13.5px;line-height:1.6;}

.action-row{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 14px 0;align-items:center;}
/* Linear button style — flat panel bg, hairline border, slight bg
   shift on hover (no transform). Primary is solid accent on dark, no
   gradient (Linear keeps buttons calm). */
.btn{
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--text); padding:6px 12px; border-radius:var(--r-md);
  font-size:12.5px; cursor:pointer; font-family:inherit; font-weight:500;
  display:inline-flex; align-items:center; gap:6px;
  transition:background-color 0.12s, border-color 0.12s, color 0.12s;
  letter-spacing:-0.003em; line-height:1.4;
}
.btn:hover{background:var(--panel2); border-color:var(--border-2);}
.btn:active{background:var(--panel);}
.btn-kc{display:inline-flex;align-items:center;gap:6px;}
.kc-chev{transition:transform 0.18s ease;flex-shrink:0;opacity:0.7;}
.btn-kc.primary .kc-chev{transform:rotate(180deg);}
.btn.primary{
  background:var(--accent); color:#fff; border-color:transparent;
  font-weight:500;
}
.btn.primary:hover{background:#7e7dff; box-shadow:none;}
.btn-meta{color:var(--muted);font-size:11.5px;margin-left:auto;}

/* ----- Indicator pills ----------------------------------------------- */
.ind-group{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0;align-items:center;}
.ind-label{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:0.08em;
  margin-right:6px;font-weight:600;}
/* Linear pill — flat panel-elev background, hairline border, mono
   text in a near-neutral colour. Variants get a tinted *colour* on
   the text only, never a saturated bg fill. */
.ind{
  background:var(--panel-elev); border:1px solid var(--border); border-radius:4px;
  padding:2px 7px; font-size:11px; font-family:var(--mono);
  color:var(--text); transition:border-color 0.12s, color 0.12s;
  cursor:default; line-height:1.5; font-weight:500;
}
.ind.cve{color:#e2a93f;}
.source-badges{display:flex; gap:6px; flex-wrap:wrap; margin:6px 0 2px;}
.source-badge{
  font-size:10.5px; font-weight:500; letter-spacing:0.01em;
  padding:2px 8px; border-radius:4px;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted); display:inline-flex; align-items:center; gap:4px;
}
/* Source badges — colour the text only; keep the bg/border neutral.
   Linear style avoids saturated colour blocks; the eye should land
   on text content, not chrome. */
.source-badge.thn{color:#7170ff;}
.source-badge.bc{color:#eb5757;}
.source-badge.ms{color:#9b8afb;}
.source-badge.kev{color:#e2a93f;}
.source-badge.talos{color:#4cb782;}
.source-badge.securelist{color:#4cb782;}
.source-badge.sentinel{color:#9b8afb;}
.source-badge.unit42{color:#e2a93f;}
.source-badge.eset{color:#7170ff;}
.source-badge.lab52{color:#4cb782;}
.source-badge.csn{color:#f25555;}
.ind.tech{color:#9b8afb; cursor:pointer;}
.ind.tech:hover{border-color:rgba(155,138,251,0.4); color:#b4a4ff;}
.ind.malware{color:#eb5757;}

/* ----- 3D Kill Chain ------------------------------------------------- */
.killchain{
  display:none; padding:20px; margin:14px 0 20px 0;
  background:linear-gradient(180deg, rgba(0,0,0,0.25), rgba(0,0,0,0.05));
  border:1px solid var(--border);
  border-radius:var(--r-lg);
  perspective:1400px;
  animation:fadeUp 0.35s cubic-bezier(0.2,0.8,0.2,1);
}
.killchain.active{display:block;}
@keyframes fadeUp{from{opacity:0;transform:translateY(-6px);}to{opacity:1;transform:translateY(0);}}

.kc3d{
  display:grid; grid-template-columns:repeat(7, minmax(0,1fr));
  gap:10px; transform-style:preserve-3d;
  transform:rotateX(8deg);
  margin:6px 0 22px 0;
}
.kc3d .kc-cell{
  position:relative; padding:14px 10px 12px;
  border-radius:10px;
  background:linear-gradient(180deg, #1a2230 0%, #0e1420 100%);
  border:1px solid #2a3445;
  text-align:center; min-height:96px;
  display:flex; flex-direction:column; justify-content:center; align-items:center;
  transform-style:preserve-3d; transition:transform 0.25s cubic-bezier(0.2,0.8,0.2,1);
  box-shadow:0 6px 14px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.04);
}
.kc3d .kc-cell:hover{transform:translateZ(12px) rotateX(-4deg);}
.kc3d .kc-cell::before{
  content:""; position:absolute; inset:1px; border-radius:9px; pointer-events:none;
  background:linear-gradient(180deg, rgba(255,255,255,0.04), transparent 30%);
}
.kc3d .kc-cell .num{
  font-size:9.5px; color:var(--muted); font-weight:700;
  letter-spacing:0.12em; text-transform:uppercase;
}
.kc3d .kc-cell .name{
  font-size:12px; font-weight:700; margin-top:4px; letter-spacing:-0.01em;
}
.kc3d .kc-cell .marker{
  font-size:9.5px; color:var(--muted-2); margin-top:6px;
  text-transform:uppercase; letter-spacing:0.1em; font-weight:700;
}
.kc3d .kc-cell.hit{
  background:linear-gradient(180deg, #3a1820 0%, #20111a 100%);
  border-color:#ff5d6d;
  box-shadow:
    0 8px 22px rgba(255,93,109,0.32),
    0 0 0 1px rgba(255,93,109,0.45) inset,
    inset 0 1px 0 rgba(255,255,255,0.06);
  animation:hit-glow 2.4s ease-in-out infinite;
}
@keyframes hit-glow{
  0%,100%{box-shadow:0 8px 22px rgba(255,93,109,0.28),0 0 0 1px rgba(255,93,109,0.4) inset, inset 0 1px 0 rgba(255,255,255,0.06);}
  50%{box-shadow:0 8px 32px rgba(255,93,109,0.5),0 0 0 1px rgba(255,93,109,0.7) inset, inset 0 1px 0 rgba(255,255,255,0.08);}
}
.kc3d .kc-cell.hit .marker{color:var(--bad);}
.kc3d .kc-cell.inferred{
  background:linear-gradient(180deg, #322218 0%, #1a1410 100%);
  border-color:#cc8a4d;
  box-shadow:0 6px 18px rgba(255,176,96,0.18), 0 0 0 1px rgba(255,176,96,0.35) inset,
    inset 0 1px 0 rgba(255,255,255,0.04);
}
.kc3d .kc-cell.inferred .marker{color:var(--warn);}

.kc-detail{font-size:12.5px;color:var(--muted);}
.kc-detail .phase-line{
  margin:6px 0; padding:8px 12px; border-radius:8px;
  background:rgba(255,255,255,0.015); border:1px solid var(--hairline);
}
.kc-detail .phase-line strong{color:var(--text);font-weight:700;}
.kc-detail .phase-line.hit{
  background:linear-gradient(90deg, rgba(255,93,109,0.08), transparent);
  border-color:rgba(255,93,109,0.3);
}
.kc-detail .phase-line.hit strong{color:var(--bad);}
.kc-detail .phase-line.inferred{
  background:linear-gradient(90deg, rgba(255,176,96,0.06), transparent);
  border-color:rgba(255,176,96,0.25);
}
.kc-detail .phase-line.inferred strong{color:var(--warn);}
.kc-detail .phase-line em{color:var(--accent-2);font-style:normal;font-size:11.5px;}

/* ----- Use case accordion ------------------------------------------- */
.usecases{display:flex;flex-direction:column;gap:12px;}
details.uc{
  background:var(--panel-elev); border:1px solid var(--border);
  border-radius:var(--r-md); transition:border-color 0.15s, box-shadow 0.15s;
  overflow:hidden;
}
details.uc[open]{border-color:var(--border-2);box-shadow:var(--shadow-sm);}
details.uc summary{
  cursor:pointer; padding:14px 16px; list-style:none;
  display:flex; flex-wrap:wrap; align-items:center; gap:10px;
  transition:background 0.12s;
}
details.uc summary:hover{background:rgba(255,255,255,0.02);}
details.uc summary::-webkit-details-marker{display:none;}
details.uc summary::before{
  content:"›"; color:var(--muted); font-size:18px; line-height:1;
  margin-right:4px; transition:transform 0.18s; display:inline-block;
}
details.uc[open] summary::before{transform:rotate(90deg);}
.uc-title{font-weight:600; font-size:13.5px; flex:1; min-width:200px;letter-spacing:-0.012em;}
.uc-phase, .uc-conf, .uc-dm{
  font-size:10px; text-transform:uppercase; letter-spacing:0.05em;
  padding:2px 8px; border-radius:4px; font-weight:500;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted);
}
.uc-phase{color:#9b8afb;}
.uc-conf.high{color:#4cb782;}
.uc-conf.medium{color:#e2a93f;}
.uc-conf.low{color:var(--muted);}
.uc-body{padding:0 16px 16px 16px;}
.uc-desc{color:var(--text);opacity:0.88;font-size:12.8px;margin:6px 0 12px 0;line-height:1.6;}
.uc-meta{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0;}

.tabs{
  display:flex; gap:2px; padding:3px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); margin:12px 0 0 0; width:fit-content;
}
.tab-btn{
  padding:5px 12px; background:transparent; border:none; border-radius:4px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:12px;
  font-weight:500; transition:color 0.12s, background-color 0.12s; letter-spacing:-0.003em;
}
.tab-btn:hover{color:var(--text); background:rgba(255,255,255,0.03);}
.tab-btn.active{
  color:var(--text);
  background:var(--panel-elev);
  box-shadow:inset 0 0 0 1px var(--border);
}
.tab-content{display:none;}
.tab-content.active{display:block;animation:fadeIn 0.2s ease;}
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}

pre{
  background:var(--code-bg); border:1px solid var(--border);
  border-radius:var(--r-md); padding:14px 16px; overflow:auto;
  font-size:12.5px; font-family:var(--mono);
  line-height:1.65; margin:10px 0;
  position:relative;
  font-feature-settings:"calt" off;
  /* Never let a long unbreakable KQL line burst out of its parent.
     max-width:100% caps the box; min-width:0 lets it shrink inside
     flex/grid items (which default min-width to min-content). */
  max-width:100%; min-width:0;
}
pre::-webkit-scrollbar{height:8px;width:8px;}
pre::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:4px;}
pre code{color:var(--text);white-space:pre;font-family:inherit;}
.copy-btn{
  position:absolute; top:10px; right:10px;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted); padding:3px 10px; border-radius:var(--r-sm);
  font-size:10.5px; font-weight:500; cursor:pointer; font-family:inherit;
  transition:color 0.12s, border-color 0.12s; opacity:0.75; letter-spacing:0.02em;
}
.copy-btn:hover{color:var(--text); border-color:var(--border-2); opacity:1;}
pre:hover .copy-btn{opacity:1;}
.copy-btn:hover{background:var(--accent);color:#04111d;border-color:transparent;}
.copy-btn.copied{background:var(--good);color:#04130a;border-color:transparent;}

/* ----- Search overlay (Cmd/Ctrl+K command palette) ------------------- */
.search-overlay{
  display:none; position:fixed; inset:0; z-index:200;
  background:rgba(4,7,12,0.78); backdrop-filter:blur(8px);
  align-items:flex-start; justify-content:center; padding-top:10vh;
  animation:fadeIn 0.15s ease;
}
.search-overlay.open{display:flex;}
.search-modal{
  width:min(720px, 92%);
  background:var(--panel-elev); border:1px solid var(--border-2);
  border-radius:var(--r-lg); box-shadow:var(--shadow-lg);
  overflow:hidden; display:flex; flex-direction:column;
  max-height:80vh;
}
.search-modal input{
  width:100%; padding:18px 22px; background:transparent; border:none;
  border-bottom:1px solid var(--hairline); color:var(--text);
  font-size:16px; font-family:inherit; outline:none;
}
.search-modal input::placeholder{color:var(--muted-2);}
.search-results{flex:1; overflow:auto; padding:6px 0;}
.search-results::-webkit-scrollbar{width:6px;}
.search-results::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:3px;}
.sr-group-head{
  display:flex; align-items:center; gap:8px;
  padding:10px 18px 6px 18px;
  font-family:var(--mono); font-size:10.5px; letter-spacing:0.06em;
  text-transform:uppercase; color:var(--muted-2);
}
.sr-group-head .sr-group-count{
  background:rgba(113,112,255,0.10); color:var(--accent-2);
  padding:1px 7px; border-radius:99px; font-size:10px;
  border:1px solid rgba(113,112,255,0.24);
}
.search-result{
  padding:9px 18px; cursor:pointer;
  display:flex; gap:12px; align-items:flex-start;
  transition:background 0.1s; border-left:2px solid transparent;
}
.search-result:hover, .search-result.sel{
  background:rgba(113,112,255,0.10);
  border-left-color:var(--accent);
}
.search-result .sr-icon{
  flex:0 0 22px; height:22px; border-radius:5px;
  display:inline-flex; align-items:center; justify-content:center;
  font-size:11px; font-weight:700; font-family:var(--mono);
  color:var(--accent-2); background:rgba(113,112,255,0.10);
  border:1px solid rgba(113,112,255,0.24);
}
.search-result.kind-art .sr-icon{color:#ff8888;background:rgba(235,87,87,0.10);border-color:rgba(235,87,87,0.32);}
.search-result.kind-uc .sr-icon{color:#9bdfc1;background:rgba(76,183,130,0.10);border-color:rgba(76,183,130,0.32);}
.search-result.kind-tech .sr-icon{color:var(--warn);background:rgba(226,169,63,0.10);border-color:rgba(226,169,63,0.32);}
.search-result.kind-actor .sr-icon{color:var(--accent-2);}
.search-result .sr-body{flex:1; min-width:0;}
.search-result .sr-title{
  font-weight:500; font-size:13.5px; margin-bottom:3px;
  color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
}
.search-result .sr-meta{
  color:var(--muted); font-size:11px;
  display:flex; gap:8px; flex-wrap:wrap; align-items:center;
  font-family:var(--mono); letter-spacing:0.02em;
}
.search-result .sr-meta .sr-badge{
  padding:1px 6px; border-radius:4px;
  background:var(--panel); border:1px solid var(--border);
  font-size:10px;
}
.search-result mark{
  background:rgba(113,112,255,0.28); color:var(--text);
  padding:0 2px; border-radius:2px;
}
.search-empty{padding:32px 20px;text-align:center;color:var(--muted);font-size:13px;}
.search-foot{
  display:flex; gap:14px; justify-content:flex-end;
  padding:8px 18px; border-top:1px solid var(--hairline);
  font-family:var(--mono); font-size:10.5px; color:var(--muted-2);
}
.search-foot .sf-key{
  background:var(--panel); border:1px solid var(--border);
  padding:1px 6px; border-radius:4px; margin-right:4px;
}

/* ----- Footer -------------------------------------------------------- */
footer{
  padding:32px 28px; text-align:center;
  color:var(--muted); font-size:11.5px;
  border-top:1px solid var(--hairline);
  margin-top:24px;
}
footer code{background:var(--panel2);padding:2px 6px;border-radius:4px;font-size:11px;}

/* ----- View tabs (Articles / ATT&CK Matrix) ----------------------------
   Linear's segmented-tab style: pill-on-pill, 1px border on the parent,
   active state is a slightly elevated panel with a subtle inner ring.
   Smaller padding, tighter type than the previous flashy version. */
.view-tabs{
  display:flex; gap:2px; padding:3px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); width:fit-content;
}
.view-tab{
  padding:6px 14px; background:transparent; border:none; border-radius:4px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:13px;
  font-weight:500; transition:color 0.12s, background-color 0.12s;
  letter-spacing:-0.005em;
  display:inline-flex; align-items:center; gap:6px;
}
.view-tab:hover{color:var(--text); background:rgba(255,255,255,0.03);}
.view-tab.active{
  color:var(--text);
  background:var(--panel-elev);
  box-shadow:inset 0 0 0 1px var(--border);
}
.view{display:none;}
.view.active{display:block;}

/* ----- ATT&CK Matrix view ------------------------------------------- */
.matrix-wrap{max-width:none; padding:18px 28px 28px;}
.matrix-toolbar{
  display:flex; gap:12px; align-items:center; flex-wrap:wrap;
  margin-bottom:14px; padding:12px 14px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md);
}
.matrix-toolbar input{
  flex:1; min-width:240px; padding:8px 12px;
  background:var(--bg); border:1px solid var(--border);
  border-radius:var(--r-sm); color:var(--text);
  font-family:inherit; font-size:13px; outline:none;
}
.matrix-toolbar input:focus{border-color:var(--accent);}
.matrix-toolbar select{
  min-width:240px; max-width:340px; padding:8px 10px;
  background:var(--bg); border:1px solid var(--border);
  border-radius:var(--r-sm); color:var(--text);
  font-family:inherit; font-size:12.5px; outline:none;
  cursor:pointer;
}
.matrix-toolbar select:focus,
.matrix-toolbar select:hover{border-color:var(--accent);}
.matrix-toolbar select option{background:var(--panel-elev); color:var(--text);}
.matrix-legend{
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); padding:10px 14px; margin-bottom:14px;
  display:flex; flex-direction:column; gap:8px;
}
.lg-row{display:flex; flex-wrap:wrap; gap:8px; align-items:center;
  font-size:11.5px; line-height:1.4;}
.lg-label{
  flex:0 0 auto; min-width:108px;
  font-size:10px; font-weight:700; letter-spacing:0.08em;
  color:var(--muted); text-transform:uppercase;
}
.lg-swatch{
  display:inline-flex; align-items:center; gap:6px;
  padding:4px 10px; border-radius:6px;
  font-size:11px; font-weight:600;
  background:var(--panel2); border:1px solid var(--border);
  color:var(--text);
}
.lg-swatch.cov-0{background:var(--panel2); color:var(--muted-2);}
.lg-swatch.cov-1{background:linear-gradient(180deg, rgba(54,224,192,0.10), rgba(54,224,192,0.02));}
.lg-swatch.cov-2{background:linear-gradient(180deg, rgba(54,224,192,0.18), rgba(54,224,192,0.04));}
.lg-swatch.cov-3{background:linear-gradient(180deg, rgba(54,224,192,0.30), rgba(54,224,192,0.06));
  border-color:rgba(54,224,192,0.35);}
.lg-swatch.cov-4{background:linear-gradient(180deg, rgba(54,224,192,0.45), rgba(54,224,192,0.10));
  border-color:rgba(54,224,192,0.55);}
.lg-swatch.heat-1{background:linear-gradient(180deg, rgba(255,176,96,0.10), rgba(255,176,96,0.02));}
.lg-swatch.heat-2{background:linear-gradient(180deg, rgba(255,93,93,0.18), rgba(255,93,93,0.04));
  border-color:rgba(255,93,93,0.4);}
.lg-swatch.heat-3{background:linear-gradient(180deg, rgba(255,50,96,0.30), rgba(255,50,96,0.06));
  border-color:rgba(255,50,96,0.55);}
.lg-chip{
  padding:3px 9px; background:var(--panel2); border:1px solid var(--border);
  border-radius:6px; font-size:11px; color:var(--text);
}
.lg-note{
  margin-left:auto; color:var(--muted-2); font-size:10.5px; font-style:italic;
}
.matrix-stats{display:flex; gap:18px; font-size:12px;}
.matrix-stats span{color:var(--muted);}
.matrix-stats span b{color:var(--text); font-variant-numeric:tabular-nums;}

/* ----- Threat Actors tab --------------------------------------------- */
.actors-wrap{
  /* Widened to 1600px now that the MITRE Groups merge brings ~140
     more entries into the grid — gives 4-column card layout breathing
     room on 1440-2560px monitors. */
  max-width:1600px; margin:0 auto; padding:18px 28px 60px;
}

/* ----- World map (Threat Actors hero) -------------------------------- */
.actors-map-wrap{
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-lg); padding:16px 20px 12px;
  margin-bottom:16px;
}
.actors-map-head{
  display:flex; gap:14px; align-items:flex-start;
  justify-content:space-between; flex-wrap:wrap;
  margin-bottom:8px;
}
.actors-map-head h3{
  margin:0; font-size:15px; font-weight:600;
  color:var(--text); letter-spacing:-0.012em;
}
.actors-map-head p{
  margin:4px 0 0; font-size:12px; color:var(--muted);
  max-width:680px; line-height:1.5;
}
.actors-map-tools{
  display:flex; gap:14px; align-items:center; flex-wrap:wrap;
}
.actors-map-legend{
  display:flex; gap:14px; align-items:center;
  font-size:11.5px; color:var(--muted-2);
  text-transform:lowercase; letter-spacing:0.02em;
  flex-wrap:wrap;
}
/* Clear-filters button — disabled / muted when nothing is filtered;
   activates with an indigo accent + count badge when something is. */
.actors-clear-btn{
  display:inline-flex; align-items:center; gap:6px;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted); padding:6px 12px; border-radius:var(--r-md);
  font-size:12px; font-weight:500; font-family:inherit;
  cursor:pointer; line-height:1;
  transition:background 0.12s, border-color 0.12s, color 0.12s;
}
.actors-clear-btn:hover:not(:disabled){
  background:var(--panel2); border-color:var(--border-2); color:var(--text);
}
.actors-clear-btn:disabled{opacity:0.4; cursor:default;}
.actors-clear-btn.has-filters{
  border-color:rgba(113,112,255,0.4);
  color:var(--text);
  background:rgba(113,112,255,0.08);
}
.actors-clear-btn.has-filters:hover{
  background:rgba(113,112,255,0.15);
  border-color:var(--accent);
}
.actors-clear-count{
  background:var(--accent); color:#fff;
  font-variant-numeric:tabular-nums;
  padding:1px 6px; border-radius:8px;
  font-size:10.5px; font-weight:600; line-height:1.4;
  display:none;
}
.actors-clear-btn.has-filters .actors-clear-count{display:inline;}
.actors-map-legend .lg-dot{
  display:inline-block; width:8px; height:8px; border-radius:50%;
  margin-right:4px; vertical-align:middle;
}
.actors-map-legend .lg-state{background:#7170ff;}
.actors-map-legend .lg-crim{background:#eb5757;}
.actors-map-legend .lg-mixed{background:#e2a93f;}
.actors-globe{
  width:100%; height:480px;
  background:radial-gradient(ellipse at center, rgba(113,112,255,0.06) 0%, transparent 70%), #08090a;
  border-radius:var(--r-md);
  position:relative;
  overflow:hidden;
}
.actors-globe canvas{display:block; width:100% !important; height:100% !important;}
.actors-globe-loading{
  position:absolute; inset:0; display:flex;
  align-items:center; justify-content:center;
  color:var(--muted); font-size:13px;
  pointer-events:none;
}
@media(max-width:780px){
  .actors-globe{height:360px;}
}
.actors-toolbar{
  display:flex; gap:12px; align-items:center; flex-wrap:wrap;
  padding:14px 16px; margin-bottom:12px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-lg); box-shadow:var(--shadow-sm);
}
.actors-toolbar input{
  flex:1 1 320px; min-width:240px;
  background:var(--panel-elev); border:1px solid var(--border); color:var(--text);
  padding:8px 14px; border-radius:var(--r-md); font-size:13.5px; font-family:inherit;
}
.actors-toolbar input:focus{border-color:var(--accent); outline:none;}
.actors-toolbar select{
  background:var(--panel-elev); border:1px solid var(--border); color:var(--text);
  padding:8px 12px; border-radius:var(--r-md); font-size:13px;
  font-family:inherit; cursor:pointer;
}
.actors-toolbar select:focus{border-color:var(--accent); outline:none;}

/* ----- Hero stats card at top of Threat Actors tab ------------------- */
.actors-hero{
  display:flex; gap:32px; flex-wrap:wrap;
  padding:18px 22px; margin-bottom:14px;
  background:linear-gradient(135deg, rgba(113,112,255,0.06), rgba(155,138,251,0.04));
  border:1px solid var(--border); border-radius:var(--r-lg);
}
.actors-hero .hero-stat{display:flex; flex-direction:column; gap:2px;}
.actors-hero .hero-stat .v{
  font-size:24px; font-weight:600; color:var(--text);
  font-variant-numeric:tabular-nums; letter-spacing:-0.018em;
  line-height:1.1;
}
.actors-hero .hero-stat .l{
  font-size:10.5px; color:var(--muted-2);
  text-transform:uppercase; letter-spacing:0.06em; font-weight:500;
}

/* ----- Multi-group filter row (mirrors articles filter-toolbar) ----- */
.actors-filters{
  display:flex; flex-direction:column; gap:8px;
  padding:14px 16px; margin-bottom:12px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-lg);
}
.actors-filters .ft-group{
  display:flex; align-items:center; gap:10px;
  flex-wrap:wrap; padding:4px 0;
}
.actors-filters .ft-group + .ft-group{
  border-top:1px dashed var(--hairline); padding-top:10px;
}
.actors-filters .ft-label{
  flex:0 0 auto; min-width:80px;
  color:var(--muted-2); font-size:10.5px;
  font-weight:600; letter-spacing:0.08em; text-transform:uppercase;
}
.actors-filters .ft-chips{
  display:flex; gap:6px; flex-wrap:wrap; align-items:center;
}
.actors-country-chips{
  display:flex; gap:6px; flex-wrap:wrap; align-items:center;
}
.actors-country-chip{
  padding:5px 11px; border-radius:var(--r-md);
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted); cursor:pointer; font-size:12px;
  font-weight:500; transition:color 0.12s, border-color 0.12s;
  display:inline-flex; align-items:center; gap:6px;
}
.actors-country-chip:hover{color:var(--text); border-color:var(--border-2);}
.actors-country-chip.active{
  background:var(--panel2); color:var(--text);
  border-color:var(--border-2);
  box-shadow:inset 2px 0 0 var(--accent);
}
.actors-country-chip .cnt{
  color:var(--muted-2); font-variant-numeric:tabular-nums;
  font-size:10.5px;
}
.actors-stats-row{
  display:flex; gap:18px; padding:8px 4px 16px; flex-wrap:wrap;
  font-size:12px; color:var(--muted);
}
.actors-stats-row b{
  color:var(--text); font-weight:600; font-variant-numeric:tabular-nums;
}
.actors-grid{
  display:grid; gap:14px;
  grid-template-columns:repeat(auto-fill, minmax(320px, 1fr));
}
.actor-card{
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-lg); padding:16px 18px;
  cursor:pointer; transition:border-color 0.15s, background-color 0.15s;
  display:flex; flex-direction:column; gap:10px;
  position:relative; overflow:hidden;
}
/* Recency stripe — left edge bar coloured by activity in the
   trailing 7 days (red), 30 days (amber), older (muted). */
.actor-card.recent-7d::before{
  content:""; position:absolute; left:0; top:0; bottom:0;
  width:3px; background:var(--bad);
}
.actor-card.recent-30d::before{
  content:""; position:absolute; left:0; top:0; bottom:0;
  width:3px; background:var(--warn);
}
/* Top-3 ATT&CK techniques shown as small mono pills */
.actor-card .ac-top-techs{
  display:flex; gap:4px; flex-wrap:wrap;
  font-family:var(--mono); font-size:10.5px;
}
.actor-card .ac-top-techs .ac-tt{
  padding:1px 6px; border-radius:3px;
  background:var(--panel-elev); border:1px solid var(--border);
  color:#9b8afb;
}
/* Severity distribution bar — horizontal stacked pixels */
.actor-card .ac-sevbar{
  display:flex; gap:1px; height:4px; border-radius:2px; overflow:hidden;
  background:var(--panel-elev);
}
.actor-card .ac-sevbar > div{height:100%;}
.actor-card .ac-sevbar .crit{background:var(--crit);}
.actor-card .ac-sevbar .high{background:var(--bad);}
.actor-card .ac-sevbar .med{background:var(--warn);}
.actor-card .ac-sevbar .low{background:var(--muted);}
.actor-card .ac-last-seen{
  font-size:10.5px; color:var(--muted-2);
  margin-top:-2px;
}
.actor-card:hover{
  border-color:var(--border-2);
  background:var(--panel-elev);
}
.actor-card .ac-head{
  display:flex; align-items:center; gap:10px;
}
.actor-card .ac-flag{
  font-size:28px; line-height:1;
  filter:drop-shadow(0 1px 2px rgba(0,0,0,0.3));
}
.actor-card .ac-title{
  flex:1; min-width:0;
}
.actor-card .ac-name{
  font-size:15px; font-weight:600; letter-spacing:-0.012em; color:var(--text);
}
.actor-card .ac-country{
  font-size:11px; color:var(--muted-2); margin-top:2px;
  text-transform:uppercase; letter-spacing:0.04em;
}
.actor-card .ac-mot{
  font-size:9.5px; padding:2px 7px; border-radius:4px;
  text-transform:uppercase; letter-spacing:0.06em; font-weight:600;
  background:var(--panel-elev); border:1px solid var(--border); color:var(--muted);
  align-self:flex-start;
}
.actor-card .ac-mot.state{color:#9b8afb; border-color:rgba(155,138,251,0.3);}
.actor-card .ac-mot.criminal{color:#eb5757; border-color:rgba(235,87,87,0.3);}
.actor-card .ac-aliases{
  font-size:11.5px; color:var(--muted); line-height:1.5;
  font-family:var(--mono);
}
.actor-card .ac-stats{
  display:grid; grid-template-columns:repeat(3, 1fr); gap:8px;
  border-top:1px solid var(--border); padding-top:10px;
}
.actor-card .ac-stat{
  display:flex; flex-direction:column; gap:2px;
}
.actor-card .ac-stat .v{
  font-size:16px; font-weight:600; color:var(--text);
  font-variant-numeric:tabular-nums; letter-spacing:-0.012em;
}
.actor-card .ac-stat .l{
  font-size:9.5px; color:var(--muted-2);
  text-transform:uppercase; letter-spacing:0.06em; font-weight:500;
}
/* Per-actor UC accordion inside the drawer. Each row is a <details>
   element; clicking the summary expands a panel that lazy-renders
   a clone of the source article's UC body (SPL/KQL tabs, techniques,
   data sources). Mirrors the inline-detection-content pattern from
   article cards but localised to a single actor. */
.actor-uc-list{display:flex; flex-direction:column; gap:6px;}
.actor-uc-row{
  background:var(--panel); border:1px solid var(--border);
  border-left:3px solid var(--border);
  border-radius:var(--r-md);
  font-size:12.5px; color:var(--text);
  overflow:hidden;
  transition:border-color 0.12s;
}
.actor-uc-row.is-llm{border-left-color:var(--accent);}
.actor-uc-row[open]{border-color:var(--border-2);}
.actor-uc-row > summary{
  padding:9px 12px; cursor:pointer; user-select:none;
  display:flex; align-items:center; gap:8px;
  list-style:none;                     /* Firefox triangle */
}
.actor-uc-row > summary::-webkit-details-marker{display:none;}
.actor-uc-row > summary:hover{background:var(--panel-elev);}
.actor-uc-row .uc-llm-pill{
  font-size:9px; padding:1px 5px; border-radius:3px;
  background:rgba(113,112,255,0.15); color:var(--accent);
  border:1px solid rgba(113,112,255,0.30); font-weight:600;
  text-transform:uppercase; letter-spacing:0.06em;
}
.actor-uc-row .uc-name{flex:1; min-width:0;}
.actor-uc-row .uc-techs{
  font-family:var(--mono); font-size:10.5px; color:var(--muted-2);
}
.actor-uc-row .uc-arrow{
  color:var(--muted-2); font-size:11px;
  transition:transform 0.18s;
}
.actor-uc-row[open] .uc-arrow{transform:rotate(180deg);}
.actor-uc-body{
  padding:0;                /* the cloned uc-body has its own padding */
  border-top:1px solid var(--border);
  background:var(--panel-elev);
  animation:fadeIn 0.18s ease;
}
.actor-uc-body[data-loaded="false"]:empty{display:none;}
.actor-uc-body .uc-body{padding:14px 16px;}
.actor-uc-foot{
  padding:8px 16px 12px;
  border-top:1px dashed var(--hairline);
}
.actor-uc-foot .actor-uc-srcart{
  color:var(--accent); font-size:11.5px; text-decoration:none;
  font-family:var(--mono);
}
.actor-uc-foot .actor-uc-srcart:hover{text-decoration:underline;}
/* Drawer severity-bar — bigger version of the card's stripe */
.actor-drawer-sev{
  display:flex; gap:2px; height:8px; border-radius:4px; overflow:hidden;
  background:var(--panel-elev); margin:6px 0;
}
.actor-drawer-sev > div{height:100%;}
.actor-drawer-sev .crit{background:var(--crit);}
.actor-drawer-sev .high{background:var(--bad);}
.actor-drawer-sev .med{background:var(--warn);}
.actor-drawer-sev .low{background:var(--muted);}
.actor-drawer-dates{
  display:flex; gap:18px; font-size:11.5px; color:var(--muted);
  margin-bottom:4px;
}
.actor-drawer-dates strong{color:var(--text); font-variant-numeric:tabular-nums;}

.actors-empty{
  text-align:center; padding:40px 16px; color:var(--muted);
  background:var(--panel); border:1px dashed var(--border);
  border-radius:var(--r-lg);
}
.actors-footer{
  margin-top:24px; padding-top:16px; border-top:1px solid var(--hairline);
  font-size:12px; color:var(--muted-2); line-height:1.6;
}
.actors-footer a{color:var(--accent); text-decoration:none;}
.actors-footer a:hover{text-decoration:underline;}

/* ----- Workflow tab -------------------------------------------------- */
.workflow-wrap{
  max-width:1280px; margin:0 auto; padding:20px 28px 60px; line-height:1.65;
}
.wf-title{
  font-size:24px; font-weight:700; letter-spacing:-0.012em;
  margin:0 0 10px 0; color:var(--text);
}
.wf-lede{
  color:var(--muted); font-size:14px; max-width:880px; margin:0 0 24px 0;
}
.wf-diagram{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--r-lg);
  padding:14px; margin:18px 0 28px 0; box-shadow:var(--shadow-sm);
  overflow:auto;
}
.wf-diagram svg{display:block; width:100%; height:auto; min-width:1100px;}
.wf-section-title{
  font-size:16px; font-weight:700; letter-spacing:-0.005em;
  color:var(--accent); margin:24px 0 8px 0;
  padding-bottom:6px; border-bottom:1px solid var(--border);
}
.wf-step{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--r-md);
  padding:14px 18px; margin-bottom:14px; font-size:13.5px; color:var(--text);
  line-height:1.65;
}
.wf-step ul, .wf-step ol{padding-left:22px; margin:6px 0;}
.wf-step li{margin-bottom:4px;}
.wf-step code{
  background:var(--panel-elev); padding:1px 6px; border-radius:4px;
  font-size:12px; color:var(--accent-3);
}
.wf-step a{color:var(--accent); text-decoration:none;}
.wf-step a:hover{text-decoration:underline;}

/* About tab cards — richer than wf-step, used for the platform-coverage
   table, Discord CTA, and how-a-UC-lands-here sections. Single column on
   narrow viewports, no internal grid. Generous padding so headings and
   body copy aren't crammed. */
.wf-card{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--r-lg);
  padding:22px 26px; margin-bottom:18px; color:var(--text);
  line-height:1.65; font-size:14px;
  box-shadow:var(--shadow-sm);
}
.wf-card h3{
  margin:0 0 12px 0; font-size:17px; font-weight:700;
  letter-spacing:-0.005em; color:var(--text);
  padding-bottom:10px; border-bottom:1px solid var(--border);
}
.wf-card p{margin:0 0 12px 0;}
.wf-card p:last-child{margin-bottom:0;}
.wf-card ul, .wf-card ol{padding-left:22px; margin:6px 0 12px 0;}
.wf-card li{margin-bottom:6px;}
.wf-card code{
  background:var(--panel-elev); padding:1px 6px; border-radius:4px;
  font-size:12.5px; color:var(--accent-3);
}
.wf-card a{color:var(--accent); text-decoration:none;}
.wf-card a:hover{text-decoration:underline;}
.wf-card em{color:var(--muted);}

/* About tab platform-coverage table */
.wf-table{
  width:100%; border-collapse:separate; border-spacing:0;
  font-size:13.5px; line-height:1.55;
  border:1px solid var(--border); border-radius:var(--r-md);
  overflow:hidden;
}
.wf-table thead th{
  background:var(--panel-elev); color:var(--muted);
  text-align:left; padding:10px 14px;
  font-weight:600; font-size:11.5px;
  text-transform:uppercase; letter-spacing:0.06em;
  border-bottom:1px solid var(--border);
}
.wf-table tbody td{
  padding:14px; vertical-align:top;
  border-bottom:1px solid var(--border);
  color:var(--text);
}
.wf-table tbody tr:last-child td{border-bottom:none;}
.wf-table tbody tr:nth-child(even) td{background:rgba(255,255,255,0.012);}
.wf-table tbody td:first-child{
  white-space:nowrap; min-width:180px;
  font-weight:600;
}
.wf-table tbody td:nth-child(2){
  white-space:nowrap; width:1%;
}
.wf-table code{
  background:var(--panel-elev); padding:1px 5px; border-radius:3px;
  font-size:11.5px; color:var(--accent-3);
}
@media(max-width:780px){
  .wf-table thead{display:none;}
  .wf-table tbody td{display:block; border-bottom:none;}
  .wf-table tbody tr{
    display:block; padding:10px 0;
    border-bottom:1px solid var(--border);
  }
  .wf-table tbody td:first-child{font-size:15px; padding-bottom:4px;}
  .wf-table tbody td:nth-child(2){padding:4px 14px 8px;}
}

/* ----- Drawer use-case list (paginated for large drawers) ------------ */
.drawer-uc-toolbar{
  display:flex; gap:8px; align-items:center; margin-bottom:10px; flex-wrap:wrap;
}
.drawer-uc-toolbar input{
  flex:1; min-width:160px;
  background:var(--panel-elev); border:1px solid var(--border); color:var(--text);
  padding:6px 10px; border-radius:var(--r-md); font-size:12px; font-family:inherit;
}
.drawer-uc-toolbar input:focus{border-color:var(--accent);}
.drawer-uc-toolbar select{
  background:var(--panel-elev); border:1px solid var(--border); color:var(--text);
  padding:6px 10px; border-radius:var(--r-md); font-size:12px; font-family:inherit;
}
.drawer-uc-pager{
  margin-top:10px; padding:8px;
  background:var(--panel); border:1px dashed var(--border); border-radius:var(--r-md);
  text-align:center; font-size:11.5px; color:var(--muted);
  cursor:pointer;
}
.drawer-uc-pager:hover{border-color:var(--accent); color:var(--accent);}
.uc-card-row .uc-src-pill{
  font-size:9.5px; padding:1px 6px; border-radius:4px;
  background:var(--panel2); color:var(--muted-2);
  text-transform:uppercase; letter-spacing:0.06em; font-weight:600;
}
.uc-card-row .uc-src-pill.escu{color:var(--accent-3);}
.uc-card-row .uc-src-pill.internal{color:var(--accent);}
/* Tier pills: alerting (production-ready) vs hunting (needs tuning).
   Alerting has a strong colour stop so high-fidelity content stands out
   in a long drawer list; hunting is muted to signal "needs review". */
.uc-card-row .uc-tier-pill{
  font-size:9.5px; padding:1px 7px; border-radius:4px;
  text-transform:uppercase; letter-spacing:0.06em; font-weight:700;
  flex:0 0 auto;
}
.uc-card-row .uc-tier-pill.alerting{
  background:rgba(46,213,99,0.18); color:var(--good);
  border:1px solid rgba(46,213,99,0.4);
}
.uc-card-row .uc-tier-pill.hunting{
  background:rgba(255,176,96,0.10); color:var(--warn);
  border:1px solid rgba(255,176,96,0.3);
}
.uc-card-row.tier-alerting{
  border-left:3px solid rgba(46,213,99,0.55);
}
.uc-card-row.tier-hunting{
  border-left:3px solid rgba(255,176,96,0.45);
}
.uc-card-row{transition:border-color 0.15s, background 0.15s;}
.uc-card-row:hover{border-color:var(--accent); background:var(--panel-elev);}
.uc-card-row .uc-card-chev{transition:transform 0.15s ease;}
.matrix-mode{display:flex; gap:4px;
  padding:3px; background:var(--bg); border:1px solid var(--border);
  border-radius:var(--r-sm);}
.matrix-mode button{
  padding:5px 12px; background:transparent; border:none; border-radius:4px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:11.5px;
  font-weight:600; letter-spacing:0.04em; text-transform:uppercase;
  transition:all 0.12s;
}
.matrix-mode button.on{background:var(--accent); color:#04111d;}

.matrix-grid{
  display:grid; grid-template-columns:repeat(14, minmax(150px, 1fr));
  gap:8px;
  overflow-x:auto; padding-bottom:24px;
}
.tactic-col{display:flex; flex-direction:column; min-width:150px;}
.tactic-header{
  position:sticky; top:0; z-index:5;
  background:var(--panel-elev); border:1px solid var(--border);
  border-radius:6px 6px 0 0;
  padding:9px 8px 7px; text-align:center;
  font-size:11px; font-weight:700; letter-spacing:0.02em;
}
.tactic-header .tactic-name{color:var(--text); display:block; line-height:1.25;}
.tactic-header .tactic-count{color:var(--muted); font-size:10px; font-weight:500;}
.tactic-techs{display:flex; flex-direction:column; gap:2px; padding-top:2px;}
.tech-cell{
  background:var(--panel); border:1px solid var(--border);
  border-radius:0; padding:5px 7px;
  font-size:11px; line-height:1.3; cursor:pointer;
  position:relative; transition:all 0.1s;
  display:flex; flex-direction:column; gap:2px;
}
.tech-cell:hover{border-color:var(--accent); transform:translateY(-1px);
  box-shadow:0 4px 10px rgba(0,0,0,0.4); z-index:2;}
.tech-cell .tech-name{color:var(--text); white-space:nowrap; overflow:hidden;
  text-overflow:ellipsis; font-weight:500;}
.tech-cell .tech-meta{display:flex; gap:6px; align-items:center; font-size:9.5px;
  color:var(--muted-2); font-variant-numeric:tabular-nums;}
.tech-cell .sub-marker{color:var(--accent-2); font-size:9px; font-weight:700;}
.tech-cell .uc-count{color:var(--accent-3); font-weight:700;}
/* Platform-coverage badges on each technique cell. Tiny pill per
   platform that has at least one UC for that technique. */
.tech-cell .pl-badges{display:inline-flex; gap:2px; margin-left:4px;}
.pl-badge{
  display:inline-flex; align-items:center; justify-content:center;
  width:14px; height:14px; border-radius:3px;
  font-family:var(--mono); font-size:8.5px; font-weight:700;
  letter-spacing:0; line-height:1;
  border:1px solid var(--border-2);
}
.pl-badge.pl-def  { background:rgba(113,112,255,0.18); color:#9b8afb; border-color:rgba(113,112,255,0.40); }
.pl-badge.pl-sent { background:rgba(64,160,255,0.18);  color:#7fb6ff; border-color:rgba(64,160,255,0.40); }
.pl-badge.pl-sigma{ background:rgba(155,138,251,0.18); color:#cbb6ff; border-color:rgba(155,138,251,0.40); font-size:9.5px; }
.pl-badge.pl-spl  { background:rgba(76,183,130,0.16);  color:#6dd29c; border-color:rgba(76,183,130,0.40); }
.pl-badge.pl-ddog { background:rgba(120,90,200,0.18);  color:#c5b0ff; border-color:rgba(120,90,200,0.42); font-size:9.5px; }
/* Matrix platform-filter dim — applied to cells lacking the active filter. */
.tech-cell.pl-filter-dim{opacity:0.18; filter:saturate(0.5);}
.tech-cell.has-uc{background:linear-gradient(180deg, rgba(54,224,192,0.07), rgba(54,224,192,0.02));}
.tech-cell.cov-1{background:linear-gradient(180deg, rgba(54,224,192,0.10), rgba(54,224,192,0.02));}
.tech-cell.cov-2{background:linear-gradient(180deg, rgba(54,224,192,0.18), rgba(54,224,192,0.04));}
.tech-cell.cov-3{background:linear-gradient(180deg, rgba(54,224,192,0.30), rgba(54,224,192,0.06));
  border-color:rgba(54,224,192,0.35);}
.tech-cell.cov-4{background:linear-gradient(180deg, rgba(54,224,192,0.45), rgba(54,224,192,0.10));
  border-color:rgba(54,224,192,0.55);}
.tech-cell.heat-1{background:linear-gradient(180deg, rgba(255,176,96,0.10), rgba(255,176,96,0.02));}
.tech-cell.heat-2{background:linear-gradient(180deg, rgba(255,93,93,0.15), rgba(255,93,93,0.04));
  border-color:rgba(255,93,93,0.4);}
.tech-cell.heat-3{background:linear-gradient(180deg, rgba(255,50,96,0.30), rgba(255,50,96,0.05));
  border-color:rgba(255,50,96,0.55);}
.tech-cell.dim{opacity:0.35;}
.tech-cell.is-sub{padding-left:14px; border-left:2px solid var(--accent-2);
  background:var(--panel2);}
.tech-cell.expanded{border-color:var(--accent);}

/* ----- Threat Intel table -------------------------------------------- */
.intel-types{display:flex; gap:4px; padding:3px;
  background:var(--bg); border:1px solid var(--border); border-radius:var(--r-sm);}
.intel-types button{
  padding:5px 11px; background:transparent; border:none; border-radius:4px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:11.5px;
  font-weight:600; letter-spacing:0.04em; text-transform:uppercase;
  transition:all 0.12s;
}
.intel-types button.on{background:var(--accent); color:#04111d;}
.intel-table-wrap{
  overflow-x:auto; border:1px solid var(--border); border-radius:var(--r-md);
  background:var(--panel);
}
.intel-table{width:100%; border-collapse:collapse; font-size:12.5px;}
.intel-table thead th{
  position:sticky; top:0; background:var(--panel-elev);
  text-align:left; padding:10px 12px; border-bottom:1px solid var(--border);
  font-size:10.5px; text-transform:uppercase; letter-spacing:0.08em;
  color:var(--muted); font-weight:700;
}
.intel-table tbody tr{transition:background 0.12s;}
.intel-table tbody tr:hover{background:rgba(95,182,255,0.04);}
.intel-table tbody tr.dim{display:none;}
.intel-table td{padding:9px 12px; border-bottom:1px solid var(--hairline); vertical-align:top;}
.intel-table .ioc-val{
  font-family:"JetBrains Mono",ui-monospace,monospace;
  color:var(--accent-2); word-break:break-all;
}
.intel-table .type-pill, .intel-table .sev-pill{
  font-size:10px; font-weight:700; letter-spacing:0.06em; text-transform:uppercase;
  padding:2px 8px; border-radius:6px;
  background:var(--panel2); border:1px solid var(--border);
  color:var(--muted); display:inline-block;
}
.intel-table .type-pill.cve{color:var(--warn); border-color:#5a3b1f;}
.intel-table .type-pill.ipv4{color:var(--accent); border-color:rgba(95,182,255,0.3);}
.intel-table .type-pill.domain{color:var(--accent-3); border-color:rgba(54,224,192,0.3);}
.intel-table .type-pill.sha256, .intel-table .type-pill.sha1, .intel-table .type-pill.md5{
  color:var(--accent-2); border-color:rgba(180,141,255,0.3);
}
.intel-table .sev-pill.crit{color:var(--crit); border-color:rgba(255,50,96,0.55);}
.intel-table .sev-pill.high{color:var(--bad); border-color:rgba(255,93,93,0.4);}
.intel-table .sev-pill.med{color:var(--warn); border-color:rgba(255,176,96,0.4);}
.intel-table .sev-pill.low{color:var(--good); border-color:rgba(92,216,122,0.4);}
.intel-table .sources{display:flex; gap:4px; flex-wrap:wrap;}
.intel-table .article-link{color:var(--accent); text-decoration:none;
  display:inline-block; max-width:300px; overflow:hidden; text-overflow:ellipsis;
  white-space:nowrap; vertical-align:bottom;}
.intel-table .article-link:hover{text-decoration:underline;}
.intel-empty{padding:40px; text-align:center; color:var(--muted-2);}

/* ----- Intel "About this feed" expandable panel ---------------------- */
details.intel-about{
  background:linear-gradient(135deg, rgba(95,182,255,0.06), rgba(180,141,255,0.04));
  border:1px solid var(--border);
  border-radius:var(--r-md);
  margin-bottom:14px;
  overflow:hidden;
}
details.intel-about[open]{
  border-color:rgba(95,182,255,0.3);
  background:var(--panel);
}
details.intel-about summary{
  padding:14px 18px; cursor:pointer; list-style:none;
  display:flex; align-items:center; gap:14px;
}
details.intel-about summary::-webkit-details-marker{display:none;}
details.intel-about summary::after{
  content:"▾"; color:var(--muted); font-size:14px; margin-left:auto;
  transition:transform 0.2s;
}
details.intel-about[open] summary::after{transform:rotate(180deg);}
.intel-about-title{font-weight:700; font-size:14px; color:var(--text);}
.intel-about-sub{color:var(--muted); font-size:12px;}
.intel-about-body{padding:0 24px 22px; line-height:1.55;}
.intel-about-body h4{
  margin:18px 0 8px; font-size:11px;
  text-transform:uppercase; letter-spacing:0.08em; color:var(--accent-2);
}
.intel-mission{
  margin:6px 0 18px;
  padding:12px 16px;
  border-left:3px solid var(--accent);
  background:rgba(95,182,255,0.04);
  border-radius:0 6px 6px 0;
}
.intel-sources{display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:8px;}
.intel-urls{display:grid; grid-template-columns:repeat(auto-fit, minmax(280px,1fr));
  gap:6px; margin:8px 0 14px;}
.intel-urls code{
  display:block; padding:8px 10px;
  background:var(--code-bg); border:1px solid var(--border); border-radius:6px;
  font-size:11.5px; word-break:break-all;
}
.intel-urls code a{color:var(--accent); text-decoration:none;}
.intel-urls code a:hover{text-decoration:underline;}
table.intel-cols-doc{
  width:100%; border-collapse:collapse; font-size:12px; margin-top:6px;
}
table.intel-cols-doc th{
  text-align:left; padding:8px 10px;
  background:var(--panel2); border-bottom:1px solid var(--border);
  font-size:10.5px; text-transform:uppercase; letter-spacing:0.08em;
  color:var(--muted);
}
table.intel-cols-doc td{
  padding:8px 10px; border-bottom:1px solid var(--hairline);
  vertical-align:top;
}
table.intel-cols-doc code{
  background:var(--panel2); padding:2px 6px; border-radius:4px;
  font-size:11px; color:var(--accent-3);
}
ul.intel-types-doc{padding-left:20px; margin:8px 0; font-size:13px;}
ul.intel-types-doc li{margin:6px 0; line-height:1.55;}
ul.intel-types-doc code{
  background:var(--panel2); padding:1px 6px; border-radius:4px;
  font-size:11px; color:var(--accent-3);
}
.quality-bar{
  background:rgba(255,176,96,0.06); border:1px solid rgba(255,176,96,0.25);
  border-left:3px solid var(--warn); border-radius:0 6px 6px 0;
  padding:12px 16px; margin:6px 0;
}
.quality-bar p{margin:0 0 6px;}
.quality-bar ul.intel-types-doc{margin:6px 0;}

/* Drawer — centred modal covering most of the screen */
.drawer-bg{
  position:fixed; inset:0; z-index:60;
  background:rgba(0,0,0,0.65); backdrop-filter:blur(6px);
  display:none;
}
.drawer-bg.open{display:block; animation:fadeIn 0.15s;}
.drawer{
  position:fixed;
  top:50%; left:50%;
  /* Centred at ~78% of viewport, capped so it never sprawls. */
  width:min(1200px, 78vw);
  height:min(880px, 86vh);
  transform:translate(-50%, -50%) scale(0.96);
  background:var(--panel-elev);
  border:1px solid var(--border-2); border-radius:14px;
  z-index:61;
  opacity:0; pointer-events:none;
  transition:transform 0.22s cubic-bezier(0.2,0.8,0.2,1), opacity 0.18s ease;
  display:flex; flex-direction:column;
  box-shadow:0 32px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset;
  overflow:hidden;
}
.drawer.open{
  transform:translate(-50%, -50%) scale(1);
  opacity:1; pointer-events:auto;
}
@media(max-width:768px){
  .drawer{ width:96vw; height:94vh; }
}
/* Drawer body must scroll — without this, long actor profiles (lots
   of UCs + 50+ techniques + IOC list) get clipped at the bottom. */
#actorDrawerBody, #drawerBody{
  flex:1; overflow-y:auto; -webkit-overflow-scrolling:touch;
  padding-bottom:24px;
}
/* Sticky in-drawer navigation bar — used when an article is rendered
   inline. Lets the user "← Back to ActorName" or step through the
   actor's article list with prev/next, all without leaving the
   Threat Actors tab. */
.drawer-nav{
  position:sticky; top:0; z-index:5;
  display:flex; align-items:center; justify-content:space-between;
  gap:12px; padding:10px 14px;
  background:var(--panel-elev);
  border-bottom:1px solid var(--border);
}
.drawer-nav-btn{
  background:var(--panel); border:1px solid var(--border);
  color:var(--text); padding:6px 12px; border-radius:var(--r-md);
  font-size:12.5px; font-weight:500; font-family:inherit;
  cursor:pointer;
  transition:background-color 0.12s, border-color 0.12s, color 0.12s;
}
.drawer-nav-btn:hover{background:var(--panel2); border-color:var(--border-2);}
.drawer-nav-btn:disabled{opacity:0.4; cursor:default;}
.drawer-nav-btn.drawer-nav-back{font-size:12.5px;}
.drawer-nav-step{
  display:flex; align-items:center; gap:6px;
  color:var(--muted); font-size:11.5px; font-variant-numeric:tabular-nums;
}
.drawer-nav-pos{padding:0 6px;}
.drawer-article{padding:18px 20px;}
.drawer-article article.card{margin-bottom:0;}
.drawer-head{padding:18px 20px; border-bottom:1px solid var(--hairline);}
.drawer-head .tid{color:var(--accent); font-family:ui-monospace,monospace; font-size:13px;
  font-weight:700; letter-spacing:0.02em;}
.drawer-head h3{margin:6px 0 4px; font-size:18px; font-weight:700; line-height:1.25;}
.drawer-head .tactics{display:flex; flex-wrap:wrap; gap:5px; margin-top:8px;}
.drawer-head .tactic-pill{font-size:10px; padding:2px 8px; border-radius:10px;
  background:rgba(180,141,255,0.12); color:var(--accent-2);
  border:1px solid rgba(180,141,255,0.3); text-transform:uppercase;
  letter-spacing:0.04em; font-weight:700;}
.drawer-head .ext-link{display:inline-flex; align-items:center; gap:4px;
  color:var(--accent); text-decoration:none; font-size:12px; margin-top:8px;}
.drawer-head .ext-link:hover{text-decoration:underline;}
.drawer-close{position:absolute; top:14px; right:14px;
  background:transparent; border:none; color:var(--muted);
  font-size:22px; cursor:pointer; line-height:1; padding:4px 8px;
  border-radius:4px;}
.drawer-close:hover{background:var(--panel2); color:var(--text);}
.drawer-body{flex:1; overflow-y:auto; padding:14px 20px 20px;}
.drawer-body::-webkit-scrollbar{width:6px;}
.drawer-body::-webkit-scrollbar-thumb{background:var(--border-2); border-radius:3px;}
.drawer-section{margin-bottom:18px;}
.drawer-section h4{font-size:10.5px; text-transform:uppercase; letter-spacing:0.08em;
  color:var(--muted); margin:0 0 8px 0; font-weight:700;}
/* Collapsible drawer sections — analyst can hide bulky parts (linked
   UCs / IOCs / articles) so the section they care about stays in view
   without scrolling past hundreds of UC rows. Open by default; click
   summary to collapse. */
details.drawer-section{margin-bottom:18px;}
details.drawer-section > summary{
  list-style:none; cursor:pointer;
  display:flex; align-items:center; gap:8px;
  font-size:10.5px; text-transform:uppercase; letter-spacing:0.08em;
  color:var(--muted); font-weight:700;
  padding:6px 8px; margin:0 -8px 8px;
  border-radius:6px;
  transition:background 0.12s, color 0.12s;
  user-select:none;
}
details.drawer-section > summary::-webkit-details-marker{display:none;}
details.drawer-section > summary::before{
  content:"▾"; font-size:11px; color:var(--muted-2);
  transition:transform 0.18s; display:inline-block;
  width:10px;
}
details.drawer-section:not([open]) > summary::before{transform:rotate(-90deg);}
details.drawer-section > summary:hover{
  background:rgba(255,255,255,0.03); color:var(--text);
}
details.drawer-section > summary:hover::before{color:var(--accent-2);}
details.drawer-section[open] > summary{color:var(--text);}
details.drawer-section .acc-count{
  color:var(--muted-2); font-weight:500;
  text-transform:none; letter-spacing:0;
}
.drawer-list{display:flex; flex-direction:column; gap:6px;}
.drawer-list a{
  display:block; padding:8px 10px; background:var(--panel); border:1px solid var(--border);
  border-radius:6px; color:var(--text); text-decoration:none;
  font-size:12.5px; line-height:1.3; transition:all 0.12s;
}
.drawer-list a:hover{border-color:var(--accent); transform:translateX(2px);}
.drawer-list .meta{display:flex; gap:6px; margin-top:4px; font-size:10px; color:var(--muted-2);
  text-transform:uppercase; letter-spacing:0.04em; font-weight:600;}
.drawer-list .pill{padding:1px 7px; border-radius:8px;
  background:var(--panel2); border:1px solid var(--border);}
.drawer-list .pill.high{color:var(--bad); border-color:rgba(255,93,93,0.4);}
.drawer-list .pill.crit{color:var(--crit); border-color:rgba(255,50,96,0.55);}
.drawer-list .pill.med{color:var(--warn); border-color:rgba(255,176,96,0.4);}
.drawer-list .pill.low{color:var(--good); border-color:rgba(92,216,122,0.4);}
.drawer-list .pill.confhigh{color:var(--good);}
.drawer-list .pill.confmedium{color:var(--warn);}
.drawer-empty{color:var(--muted-2); font-size:12px; font-style:italic; padding:8px 0;}

/* When the Articles-tab Platform filter is active, UCs on visible
   article cards that don't have the selected platform get hidden so
   the analyst sees only the bodies they filtered for. */
details.uc.uc-platform-hidden{display:none !important;}

/* Splunk SPL nested Summarised / Non-summarised toggle. Only renders
   when the query has a tstats acceleration form that's worth toggling. */
.spl-mode-toggle{
  display:flex; gap:4px; align-items:center;
  margin:0 0 8px 0; padding:4px 6px;
  background:rgba(255,255,255,0.03);
  border:1px solid var(--border); border-radius:6px;
  flex-wrap:wrap;
}
.spl-mode-btn{
  background:transparent; border:0; color:var(--muted);
  padding:4px 10px; border-radius:4px; cursor:pointer;
  font:inherit; font-size:11px; font-weight:500;
  transition:color 0.12s, background 0.12s;
}
.spl-mode-btn:hover{color:var(--text);}
.spl-mode-btn.active{
  background:rgba(113,112,255,0.16);
  color:var(--text);
}
.spl-mode-hint{
  font-size:10.5px; color:var(--muted-2); margin-left:8px;
}
.spl-mode-body{display:none;}
.spl-mode-body.active{display:block;}

/* ----- Share buttons + deeplink highlight ---------------------------- */
.share-btn{
  background:transparent; border:1px solid transparent;
  color:var(--muted); cursor:pointer;
  padding:3px 5px; border-radius:5px;
  display:inline-flex; align-items:center; justify-content:center;
  line-height:1;
  transition:color 0.12s, border-color 0.12s, background 0.12s, transform 0.12s;
}
.share-btn:hover{
  color:var(--text); border-color:var(--border); background:rgba(255,255,255,0.04);
}
.share-btn:active{transform:scale(0.92);}
.share-btn.copied{
  color:#10b981; border-color:rgba(16,185,129,0.4); background:rgba(16,185,129,0.08);
}
.share-btn.copied svg{display:none;}
.share-btn.copied::after{content:"✓ Link copied"; font-size:11px; font-weight:600;}
/* UC inline share button: sit at end of summary row, low-emphasis. */
.uc summary .share-btn{
  margin-left:auto; opacity:0.55;
}
.uc summary:hover .share-btn{opacity:1;}
/* Article-card share button: floats top-right corner of the card. */
.card-share{
  position:absolute; top:12px; right:42px;
  width:28px; height:28px;
  opacity:0.55;
}
.card:hover .card-share{opacity:1;}
.card{position:relative;}

/* Brief halo + outline when a deeplink lands on a target. */
@keyframes deeplinkHi{
  0%   {box-shadow:0 0 0 0 rgba(113,112,255,0.55);}
  60%  {box-shadow:0 0 0 8px rgba(113,112,255,0);}
  100% {box-shadow:0 0 0 0 rgba(113,112,255,0);}
}
.deeplink-target{
  animation:deeplinkHi 1.6s ease-out 1;
  outline:1px solid var(--accent);
  outline-offset:2px;
  border-radius:6px;
}
@media (prefers-reduced-motion: reduce){
  .deeplink-target{animation:none;}
}

/* ----- Reduced motion ------------------------------------------------ */
@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{animation:none !important;transition:none !important;}
}
</style>
</head>
<body>
<!-- Logo lightbox — click logoButton to open, click backdrop or ESC to close. -->
<div class="logo-lightbox" id="logoLightbox" role="dialog" aria-modal="true" aria-labelledby="lbCaption" hidden>
  <button class="logo-lightbox-close" id="logoLightboxClose" aria-label="Close">×</button>
  <img src="logo.png" alt="Clanker the Clankerusecase mascot">
  <div class="logo-lightbox-caption" id="lbCaption"><strong>Clanker</strong> · the Clankerusecase mascot</div>
</div>
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <button type="button" class="logo" id="logoButton"
              aria-label="View Clanker the mascot at full size"
              title="Meet Clanker">
        <!-- logo.png in repo root → SVG fallback if file missing -->
        <img src="logo.png" alt="Clankerusecase" class="logo-img"
             onerror="this.style.display='none';this.nextElementSibling.style.display='block';">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="display:none;">
          <path d="M12 2 L4 6 v6 c0 5 3.5 8 8 10 4.5-2 8-5 8-10 V6z"/>
          <path d="M9 12 l2 2 l4-4"/>
        </svg>
      </button>
      <div class="brand-text">
        <span class="brand-name">Clankerusecase</span>
        <span class="brand-tagline">A threat-led detection library — production-ready queries for SOC, threat hunters, and CTI teams.</span>
      </div>
    </div>
    <div class="stats-wrap">
      <div class="stats stats-articles" id="topStats">
        <div class="stat"><div class="v">__ARTICLE_COUNT__</div><div class="l">Articles</div></div>
        <div class="stat"><div class="v">__USECASE_COUNT__</div><div class="l">Use Cases</div></div>
        <div class="stat"><div class="v">__TECH_COUNT__</div><div class="l">ATT&amp;CK</div></div>
        <div class="stat"><div class="v">__CVE_COUNT__</div><div class="l">CVEs</div></div>
        <div class="stat"><div class="v">__CRIT_COUNT__</div><div class="l">Critical</div></div>
      </div>
      <div class="stats stats-matrix" id="topStatsMatrix"></div>
      <div class="stats stats-intel" id="topStatsIntel"></div>
      <div class="stats stats-actors" id="topStatsActors"></div>
      <div class="stats stats-library" id="topStatsLibrary"></div>
    </div>
    <div class="search-trigger" id="searchTrigger">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21 L16.65 16.65"/></svg>
      <span class="search-placeholder">Search articles, techniques, CVEs</span>
      <span class="search-shortcut"><kbd id="searchShortcutKey">Ctrl</kbd><kbd>K</kbd></span>
    </div>
    <a href="cheatsheet.html" target="_blank" rel="noopener" class="cheatsheet-btn"
       title="Open the SOC analyst KQL cheat sheet in a new window">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8 H16 M8 12 H16 M8 16 H13"/></svg>
      <span>SOC Cheat Sheet</span>
    </a>
    <button type="button" class="tour-trigger" id="tourTrigger"
            title="Take the guided tour of the site (Esc to skip, ← → to navigate)">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.5 9 a3 3 0 1 1 4.5 2.5 c-1 0.7 -1.5 1 -1.5 2.5"/><circle cx="12" cy="17" r="0.6" fill="currentColor"/></svg>
      <span>Tour</span>
    </button>
  </div>
  <div class="topbar-inner" style="padding-top:0; gap:14px;">
    <div class="view-tabs" role="tablist">
      <button class="view-tab active" data-view="articles" role="tab">Articles</button>
      <button class="view-tab" data-view="library" role="tab">Detection Library</button>
      <button class="view-tab" data-view="matrix" role="tab">ATT&amp;CK Matrix</button>
      <button class="view-tab" data-view="intel" role="tab">Threat Intel</button>
      <button class="view-tab" data-view="actors" role="tab">Threat Actors</button>
      <button class="view-tab" data-view="workflow" role="tab">Workflow</button>
      <button class="view-tab" data-view="about" role="tab">About</button>
    </div>
  </div>
</header>

<div class="first-visit-banner" id="firstVisitBanner" role="region" aria-label="Welcome">
  <span class="banner-quote">“A go-to resource SOC engineers actually use daily.”</span>
  <span class="banner-explainer"><b>New here?</b> We turn daily threat-intel articles into ready-to-deploy SOC detections — every 2 hours.</span>
  <span class="banner-stats">__ARTICLE_COUNT__ articles · __USECASE_COUNT__ detections · MITRE ATT&amp;CK + Sigma · Defender · Sentinel · Splunk</span>
  <a href="#" class="banner-cta" id="firstVisitTour">Take the 30-second tour →</a>
</div>

<!-- One-time "what's new this week" banner. Dismissal persists per user
     under a versioned localStorage key; bump WHATSNEW_VERSION below to
     re-trigger for everyone after the next round of updates. -->
<div class="whatsnew-banner" id="whatsnewBanner" role="region" aria-label="What's new this week" hidden>
  <div class="wn-head">
    <span class="wn-tag">This week</span>
    <span class="wn-title">Shipped &amp; coming soon</span>
    <button type="button" class="wn-close" id="whatsnewClose" aria-label="Dismiss" title="Dismiss — won't show again">×</button>
  </div>
  <div class="wn-body">
    <div class="wn-col">
      <div class="wn-col-head">Shipped this week</div>
      <ul class="wn-list">
        <li><b>CrowdStrike</b> detection coverage added</li>
        <li><b>Kibana</b> detection coverage added</li>
        <li><b>20+ Weekly Kill-Chain use cases</b> generated from this week's threat landscape — filter by <b>WKC</b> in Detection Library</li>
      </ul>
    </div>
    <div class="wn-col">
      <div class="wn-col-head">Coming next week</div>
      <ul class="wn-list">
        <li>Per-UC <b>feedback</b> — flag logic issues so we can improve the AI</li>
        <li>More <b>community recommendations</b></li>
        <li><b>User accounts</b> so we can reply directly</li>
        <li><b>Comments on articles</b></li>
      </ul>
    </div>
  </div>
</div>

<!-- =================================================================
     Guided tour — overlay + card. Inert until startTour() is called.
     ================================================================= -->
<div class="tour-overlay" id="tourOverlay" aria-hidden="true"></div>
<div class="tour-card" id="tourCard" role="dialog" aria-modal="true" aria-labelledby="tourCardTitle" hidden>
  <div class="tour-card-header">
    <span class="tour-section" id="tourSection">Section</span>
    <span class="tour-counter" id="tourCounter">1 / 12</span>
    <button type="button" class="tour-skip" id="tourSkip" aria-label="Skip tour">Skip ×</button>
  </div>
  <h3 class="tour-title" id="tourCardTitle">Step title</h3>
  <p class="tour-body" id="tourBody">Step body text.</p>
  <div class="tour-preview" id="tourPreview"></div>
  <div class="tour-progress" id="tourProgress" aria-hidden="true"></div>
  <div class="tour-actions">
    <button type="button" class="tour-btn tour-back" id="tourBack">← Back</button>
    <button type="button" class="tour-btn tour-next" id="tourNext">Next →</button>
  </div>
  <p class="tour-hint">Esc to skip · ← → to navigate</p>
</div>

<div id="view-articles" class="view active">
<main class="width-wide">
  <nav class="toc">
    <h3>Articles</h3>
    <div id="navlist">__NAV__</div>
  </nav>
  <section id="articles">
    <!-- LLM-UC explainer: collapsed by default, click to expand. Sits above
         the source filter so analysts know what an `[LLM]` prefix means
         before they click "LLM UCs only". -->
    <details class="info-banner" id="llmInfoBanner">
      <summary>
        <span class="info-icon">ℹ︎</span>
        <strong>What's an <code>[LLM]</code> use case?</strong>
        <span class="info-hint">click to expand</span>
      </summary>
      <div class="info-body">
        <p>
          Most use cases on this site come from <strong>generic rule files</strong>
          (<code>use_cases/*.yml</code>) — they fire whenever an article mentions a
          known trigger (e.g. <code>psexec</code> → <code>UC_LATERAL_PSEXEC</code>).
          Useful, but not tailored to the specific attack.
        </p>
        <p>
          UCs prefixed <code>[LLM]</code> are different. The pipeline asks
          Claude to <strong>read the actual article</strong> and write a
          detection that hunts <em>exactly that campaign / actor / malware</em>
          — Defender KQL or Splunk SPL pinned to the IOCs and TTPs the article
          describes. Cross-checked via WebSearch against vendor advisories
          (Microsoft Threat Intel, Mandiant, CrowdStrike, MITRE, abuse.ch)
          and linked back as <em>"Cross-checked against:"</em>.
        </p>
        <p>
          They sort to the top of every article card and the matrix drawer
          because they're the highest-fidelity content here. Use the
          <strong>LLM UCs only</strong> filter below to see only articles
          where Claude generated bespoke detection logic.
        </p>
      </div>
    </details>
    <!-- Article toolbar — labelled groups so the filter surface is
         legible even as we add more groups over time. Each <div class="ft-group">
         is one logical group: a small uppercase label + its controls.
         Groups wrap on narrow viewports. -->
    <div class="filter-toolbar" id="srcFilter">
      <div class="ft-group ft-source">
        <span class="ft-label">Source</span>
        <div class="ft-chips">__SOURCE_CHIPS__</div>
      </div>
      <div class="ft-group ft-content">
        <span class="ft-label">Content</span>
        <div class="ft-chips">
          <button class="src-chip feat-chip" data-feat="has-uc"
                  title="Show only articles that have at least one detection use case">
            Has UCs <span class="cnt" id="featCntHasUc"></span>
          </button>
          <button class="src-chip feat-chip" data-feat="has-llm"
                  title="Show only articles where the LLM generated bespoke article-specific UCs">
            LLM UCs only <span class="cnt" id="featCntHasLlm"></span>
          </button>
        </div>
      </div>
      <div class="ft-group ft-platform">
        <span class="ft-label">Platform</span>
        <div class="ft-chips">
          <button class="src-chip plat-chip" data-platform="def"
                  title="Show only articles whose UCs have a Defender KQL query">
            Defender <span class="cnt" id="platCntDef"></span>
          </button>
          <button class="src-chip plat-chip" data-platform="sent"
                  title="Show only articles whose UCs have a Sentinel KQL query">
            Sentinel <span class="cnt" id="platCntSent"></span>
          </button>
          <button class="src-chip plat-chip" data-platform="sigma"
                  title="Show only articles whose UCs have a Sigma rule">
            Sigma <span class="cnt" id="platCntSigma"></span>
          </button>
          <button class="src-chip plat-chip" data-platform="spl"
                  title="Show only articles whose UCs have a Splunk SPL query">
            Splunk <span class="cnt" id="platCntSpl"></span>
          </button>
          <button class="src-chip plat-chip" data-platform="datadog"
                  title="Show only articles whose UCs have a Datadog Cloud SIEM query">
            Datadog <span class="cnt" id="platCntDatadog"></span>
          </button>
        </div>
      </div>
      <div class="ft-group ft-target">
        <span class="ft-label">Target</span>
        <div class="ft-chips" id="ftTargetChips"><!-- target chips populated by JS once MATRIX is in scope --></div>
      </div>
      <div class="ft-group ft-view">
        <span class="ft-label">Layout</span>
        <div class="width-toggle" id="widthToggle" title="Article column width">
          <button data-width="compact">Compact</button>
          <button data-width="wide" class="on">Wide</button>
          <button data-width="full">Full</button>
        </div>
      </div>
    </div>
    __CARDS__
  </section>
</main>
</div>

<div id="view-library" class="view">
  <div class="lib-wrap">
    <div class="lib-header">
      <div class="lib-title-row">
        <h2 class="lib-title">Detection Library</h2>
        <span class="lib-subtitle">Every use case, structured. Click any card for the full detection page.</span>
      </div>
      <div class="lib-toolbar">
        <input type="text" id="libSearch" placeholder="Search by name, technique, actor, app, CVE…" autocomplete="off">
        <div class="lib-result-count" id="libResultCount">—</div>
      </div>
      <div class="lib-filter-row" id="libFilters"><!-- chips populated by renderLibrary() --></div>
    </div>
    <div class="lib-grid" id="libGrid" role="list"><!-- card list populated by JS --></div>
  </div>
</div>

<!-- UC detail panel — full-width slide-in showing the structured page. -->
<div class="lib-drawer" id="libDrawer" hidden role="dialog" aria-modal="true" aria-labelledby="libDrawerTitle">
  <div class="lib-drawer-inner">
    <button type="button" class="lib-drawer-close" id="libDrawerClose" aria-label="Close">×</button>
    <div class="lib-drawer-content" id="libDrawerContent"><!-- populated on open --></div>
  </div>
</div>

<div id="view-matrix" class="view">
  <div class="matrix-wrap">
    <div class="matrix-toolbar">
      <input type="text" id="matrixSearch" placeholder="Filter by technique name or T-ID" autocomplete="off">
      <div class="matrix-mode" id="matrixModes">
        <button class="on" data-mode="coverage">Coverage</button>
        <button data-mode="heat">Heat</button>
        <button data-mode="all">All</button>
      </div>
      <div class="matrix-mode" id="matrixPlatforms" title="Filter techniques to those covered by a specific platform">
        <button class="on" data-pl="all">All platforms</button>
        <button data-pl="def" title="Defender Advanced Hunting KQL">Defender</button>
        <button data-pl="sent" title="Microsoft Sentinel KQL">Sentinel</button>
        <button data-pl="sigma" title="Platform-neutral Sigma">Sigma</button>
        <button data-pl="spl" title="Splunk SPL">SPL</button>
        <button data-pl="datadog" title="Datadog Cloud SIEM logs query">Datadog</button>
      </div>
      <div class="matrix-stats" id="matrixStats"></div>
    </div>
    <div class="matrix-legend" id="matrixLegend">
      <div class="lg-row">
        <span class="lg-label">Coverage mode</span>
        <span class="lg-swatch cov-0">none</span>
        <span class="lg-swatch cov-1">1 UC</span>
        <span class="lg-swatch cov-2">2 UCs</span>
        <span class="lg-swatch cov-3">3 UCs</span>
        <span class="lg-swatch cov-4">4+ UCs</span>
        <span class="lg-note">how many of our use cases map to that technique</span>
      </div>
      <div class="lg-row">
        <span class="lg-label">Heat mode</span>
        <span class="lg-swatch cov-0">none</span>
        <span class="lg-swatch heat-1">1 article</span>
        <span class="lg-swatch heat-2">2 articles</span>
        <span class="lg-swatch heat-3">3+ articles</span>
        <span class="lg-note">how many current articles cite that technique</span>
      </div>
      <div class="lg-row">
        <span class="lg-label">Cell badges</span>
        <span class="lg-chip"><b style="color:var(--accent-2);">▾4</b> = 4 sub-techniques</span>
        <span class="lg-chip"><b style="color:var(--accent-3);">3 UC</b> = 3 use cases mapped</span>
        <span class="lg-chip"><b style="color:var(--warn);">8 art</b> = 8 articles cite it</span>
        <span class="lg-note">click any cell for the full drawer</span>
      </div>
      <div class="lg-row">
        <span class="lg-label">Platform coverage</span>
        <span class="lg-chip"><span class="pl-badge pl-def">D</span> Defender Advanced Hunting KQL</span>
        <span class="lg-chip"><span class="pl-badge pl-sent">S</span> Sentinel KQL</span>
        <span class="lg-chip"><span class="pl-badge pl-sigma">Σ</span> Sigma rule</span>
        <span class="lg-chip"><span class="pl-badge pl-spl">P</span> Splunk SPL</span>
        <span class="lg-chip"><span class="pl-badge pl-ddog">DD</span> Datadog Cloud SIEM</span>
        <span class="lg-note">use the toolbar's platform pills to filter the matrix</span>
      </div>
    </div>
    <div class="matrix-grid" id="matrixGrid"></div>
  </div>
</div>

<div id="view-intel" class="view">
  <div class="matrix-wrap">
    <details class="intel-about" id="intelAbout">
      <summary>
        <span class="intel-about-title">📡 About the Intel Feed</span>
        <span class="intel-about-sub">Real intel from the best threat articles · click to expand</span>
      </summary>
      <div class="intel-about-body">
        <p class="intel-mission">
          <strong>Mission:</strong> Provide actionable, contextualised threat intelligence drawn from the day's
          best security reporting — not a generic IOC firehose. Every indicator below has a story attached:
          who reported it, when, and which malware/actor/campaign it relates to.
        </p>

        <h4>Sources</h4>
        <div class="intel-sources">
          <span class="source-badge thn">The Hacker News</span>
          <span class="source-badge bc">BleepingComputer</span>
          <span class="source-badge ms">Microsoft Security Blog</span>
          <span class="source-badge kev">CISA KEV</span>
          <span class="lg-note">refreshed daily · deduplicated across publications</span>
        </div>

        <h4>Pull the feed (always current)</h4>
        <div class="intel-urls">
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.csv" target="_blank">intel/iocs.csv</a></code>
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.json" target="_blank">intel/iocs.json</a></code>
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.stix.json" target="_blank">intel/iocs.stix.json</a></code>
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/splunk_lookup_iocs.csv" target="_blank">splunk_lookup_iocs.csv</a></code>
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.rss.xml" target="_blank">📡 iocs.rss.xml (RSS 2.0)</a></code>
        </div>
        <p class="lg-note" style="margin-top:6px;">
          Drop the RSS URL into Feedly, Inoreader, Slack RSS, or your TIP's RSS connector to get
          notified the moment a new high-fidelity IOC lands. The feed shows the latest 100 items,
          newest first, with severity, source attribution and a click-through to the source article.
        </p>

        <h4>What each column tells you</h4>
        <table class="intel-cols-doc">
          <tr><th>Column</th><th>What it means</th><th>What to do with it</th></tr>
          <tr><td><code>value</code></td><td>The actual indicator (CVE-ID, IP, domain, hash)</td><td>Search your telemetry for matches</td></tr>
          <tr><td><code>type</code></td><td><code>cve</code> · <code>ipv4</code> · <code>domain</code> · <code>sha256</code> · <code>sha1</code> · <code>md5</code></td><td>Routes you to the right SIEM data model / Defender table</td></tr>
          <tr><td><code>severity</code></td><td><code>crit</code> / <code>high</code> / <code>med</code> / <code>low</code> — inherited from the article</td><td>Triage priority. <code>crit</code>+<code>high</code> get hunted today</td></tr>
          <tr><td><code>sources</code></td><td>Publication(s) that reported the IOC</td><td>2+ sources = stronger consensus</td></tr>
          <tr><td><code>first_seen</code></td><td>Earliest article publication date</td><td>Bounds your hunt window</td></tr>
          <tr><td><code>article</code> link</td><td>Direct URL to the source article</td><td>Click for full context — TTPs, additional IOCs</td></tr>
        </table>

        <h4>What you're looking at — by IOC type</h4>
        <ul class="intel-types-doc">
          <li><strong>CVE</strong> — a vulnerability identifier; match against your scanner output. <code>Splunk: Vulnerabilities.signature</code> · <code>Defender: DeviceTvmSoftwareVulnerabilities.CveId</code></li>
          <li><strong>IPv4</strong> — attacker-controlled C2/scanner IP. <code>Splunk: Network_Traffic.All_Traffic.dest</code> · <code>Defender: DeviceNetworkEvents.RemoteIP</code></li>
          <li><strong>Domain</strong> — attacker hostname (C2/phishing/download). <code>Splunk: Network_Resolution.DNS.query</code> · <code>Defender: DeviceNetworkEvents.RemoteUrl</code></li>
          <li><strong>SHA256 / SHA1 / MD5</strong> — malicious file hashes. <code>Splunk: Endpoint.Filesystem.file_hash</code> · <code>Defender: DeviceFileEvents.SHA256</code></li>
        </ul>

        <h4>How we earn the SOC's trust — high-fidelity extraction</h4>
        <div class="quality-bar">
          <p>A bad IOC feed makes an analyst block legitimate Outlook / GitHub / vendor traffic. So this pipeline is deliberately conservative:</p>
          <ul class="intel-types-doc">
            <li><strong>CVEs and hashes</strong> are extracted by regex — unambiguous format, low false-positive rate.</li>
            <li><strong>Domains and IPs</strong> are accepted <em>only when defanged</em> by the source author (e.g. <code>evil[.]com</code>, <code>1[.]2[.]3[.]4</code>, <code>hxxps://...</code>). That's the universal "I'm flagging this as malicious" convention.</li>
            <li><strong>Plain-text domain/IP mentions are rejected</strong>. In an RSS summary, a phrase like "Outlook users were affected" or "ASP.NET vulnerability" is the legitimate victim or platform — never an IOC. We don't ship false positives just to look busy.</li>
          </ul>
          <p style="margin-top:10px;color:var(--muted);">
            If today's feed shows mostly CVEs, that reflects an honest reality: KEV publishes structured exploited-CVE data daily; defanged IPs/hashes typically live in technical write-ups whose bodies we cannot scrape. Every IOC you see has earned its place.
          </p>
        </div>

        <h4>Severity meaning</h4>
        <ul class="intel-types-doc">
          <li><span class="sev-pill crit">CRIT</span> — multiple sources + zero-day + active exploitation → page on-call</li>
          <li><span class="sev-pill high">HIGH</span> — confirmed exploitation, named threat actor, or CISA KEV → hunt this shift</li>
          <li><span class="sev-pill med">MED</span> — reported activity, malware family identified → weekly hunt queue</li>
          <li><span class="sev-pill low">LOW</span> — background reporting → context only</li>
        </ul>

        <p class="lg-note" style="margin-top:14px;">
          Full docs and integration examples (Splunk, Defender, MISP, OpenCTI, Sentinel TAXII): see
          <a href="https://github.com/Virtualhaggis/usecaseintel/blob/main/intel/README.md" target="_blank" style="color:var(--accent);">intel/README.md on GitHub</a>.
        </p>
      </div>
    </details>

    <div class="matrix-toolbar">
      <input type="text" id="intelSearch" placeholder="Search IOC value, article title, or context" autocomplete="off">
      <div class="intel-types" id="intelTypes">
        <button class="on" data-type="">All</button>
        <button data-type="cve">CVE</button>
        <button data-type="ipv4">IP</button>
        <button data-type="domain">Domain</button>
        <button data-type="sha256">SHA256</button>
        <button data-type="sha1">SHA1</button>
        <button data-type="md5">MD5</button>
      </div>
      <div class="matrix-stats" id="intelStats"></div>
    </div>
    <div class="matrix-toolbar" style="margin-top:-6px;">
      <span class="lg-label">Export</span>
      <button class="src-chip" data-export="csv">📄 CSV</button>
      <button class="src-chip" data-export="json">{ } JSON</button>
      <button class="src-chip" data-export="stix">⚡ STIX 2.1</button>
      <button class="src-chip" data-export="splunk">🔎 Splunk lookup</button>
      <button class="src-chip" data-export="copy">📋 Copy CSV</button>
      <a class="src-chip" target="_blank" rel="noopener"
         href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.rss.xml"
         style="text-decoration:none;color:var(--warn);border-color:rgba(255,176,96,0.4);">
        📡 Subscribe via RSS
      </a>
      <span class="lg-note" style="margin-left:auto;">Exports reflect current filters · RSS feed auto-refreshes daily</span>
    </div>
    <div class="intel-table-wrap">
      <table class="intel-table" id="intelTable">
        <thead><tr>
          <th>Value</th><th>Type</th><th>Sev</th>
          <th>Sources</th><th>Article</th><th>First seen</th><th>Articles</th>
        </tr></thead>
        <tbody id="intelBody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="drawer-bg" id="drawerBg"></div>
<aside class="drawer" id="techDrawer" aria-hidden="true">
  <button class="drawer-close" id="drawerClose" aria-label="Close">×</button>
  <div class="drawer-head" id="drawerHead"></div>
  <div class="drawer-body" id="drawerBody"></div>
</aside>

<div class="search-overlay" id="searchOverlay">
  <div class="search-modal">
    <input type="text" id="searchInput" placeholder="Search use cases, articles, techniques (T1566), actors, CVEs…" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
    <div class="search-results" id="searchResults"></div>
    <div class="search-foot">
      <span><span class="sf-key">↑↓</span>navigate</span>
      <span><span class="sf-key">⏎</span>open</span>
      <span><span class="sf-key">esc</span>close</span>
    </div>
  </div>
</div>

<!-- ===== Threat Actors tab — search by actor / country / motivation,
     sort by recency or activity, click for drill-down into linked
     articles, use cases (with SPL/KQL), techniques, IOCs. Rendered
     lazily on tab switch from window.__ACTORS__. ===== -->
<div id="view-actors" class="view">
  <div class="actors-wrap">
    <!-- 3D globe — actual rotating earth via three-globe + three.js.
         Loads from unpkg CDN (deferred). Click any pinned country to
         filter the grid. Drag to spin manually; auto-rotates slowly
         when idle. WebGL fallback: if the libs fail to load, the
         empty container takes no space and the country chip bar still
         works the same. -->
    <div class="actors-map-wrap" id="actorsMapWrap">
      <div class="actors-map-head">
        <div>
          <h3>Threat actor coverage by country</h3>
          <p>Drag to spin · click a pin to filter the grid below. Pin height = actor count, colour = indigo (state) / red (criminal) / purple (mixed).</p>
        </div>
        <div class="actors-map-tools">
          <div class="actors-map-legend">
            <span class="lg-dot lg-state"></span> state
            <span class="lg-dot lg-crim"></span> criminal
            <span class="lg-dot lg-mixed"></span> mixed
          </div>
          <button id="actorsClearFilters" class="actors-clear-btn" disabled
                  title="Reset country, motivation, and search filters">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
            <span>Clear filters</span>
            <span class="actors-clear-count" id="actorsClearCount"></span>
          </button>
        </div>
      </div>
      <div id="actorsGlobe" class="actors-globe"></div>
    </div>
    <!-- Legacy hero slot (now unused — stats moved to topbar) -->
    <div class="actors-hero" id="actorsHero" style="display:none;"></div>
    <!-- Filter toolbar: search, country chips, motivation chips, sort -->
    <div class="actors-toolbar">
      <input type="text" id="actorsSearch" placeholder="Search actor name, alias, or country (e.g. APT29, Cozy, Russia, ransomware)…" autocomplete="off">
      <select id="actorsSort" title="Sort actors">
        <option value="active">Most active</option>
        <option value="recent">Most recent</option>
        <option value="techs">Most techniques</option>
        <option value="alpha">Alphabetical</option>
      </select>
    </div>
    <div class="actors-filters">
      <div class="ft-group">
        <span class="ft-label">Country</span>
        <div class="ft-chips" id="actorsCountryChips"></div>
      </div>
      <div class="ft-group">
        <span class="ft-label">Motivation</span>
        <div class="ft-chips" id="actorsMotChips">
          <button class="actors-country-chip active" data-mot="">All</button>
          <button class="actors-country-chip" data-mot="state">State-sponsored</button>
          <button class="actors-country-chip" data-mot="criminal">Criminal</button>
          <button class="actors-country-chip" data-mot="hacktivist">Hacktivist</button>
          <button class="actors-country-chip" data-mot="unknown">Unknown</button>
        </div>
      </div>
    </div>
    <div class="actors-stats-row" id="actorsStatsRow"></div>
    <div class="actors-grid" id="actorsGrid"></div>
    <div class="actors-empty" id="actorsEmpty" style="display:none;">
      <p>No threat actors matched the current filters.</p>
    </div>
    <div class="actors-footer">
      <p>
        Threat actor names + country attribution are extracted from
        every article body via a curated alias lookup
        (<a href="https://attack.mitre.org/groups/" target="_blank">MITRE ATT&amp;CK Groups</a>,
        Mandiant, CrowdStrike Bears/Pandas/Cobras, Microsoft Threat
        Intel Typhoon naming, Unit 42 Sandstorm naming). Click any
        actor to drill into linked articles, use cases (with SPL/KQL
        you can run), ATT&amp;CK techniques, and IOCs. Click any
        technique pill in the drawer to pivot to the Matrix tab and
        see all UCs covering it.
      </p>
    </div>
  </div>
</div>

<!-- Threat-actor drawer — inline content (linked articles, UCs, IOCs) -->
<div id="actorDrawerBg" class="drawer-bg" aria-hidden="true"></div>
<aside id="actorDrawer" class="drawer" aria-hidden="true">
  <button class="drawer-close" id="actorDrawerClose" aria-label="Close">×</button>
  <div id="actorDrawerBody"></div>
</aside>

<div id="view-workflow" class="view">
  <div class="workflow-wrap">
    <h2 class="wf-title">From article to detection — the full pipeline</h2>
    <p class="wf-lede">
      How a fresh threat-intel article moves through this site: ingestion,
      extraction, mapping, export. Diagram first, then the per-step detail —
      including the actual prompts, regex, and heuristics behind each stage.
    </p>

    <!-- ============== DIAGRAM ============== -->
    <div class="wf-diagram">
      <svg viewBox="0 0 1280 480" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Pipeline workflow">
        <defs>
          <marker id="wfArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#5fb6ff"/>
          </marker>
          <linearGradient id="wfFill1" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#1a2840"/>
            <stop offset="1" stop-color="#0f1a2c"/>
          </linearGradient>
          <linearGradient id="wfFill2" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#1f2a3f"/>
            <stop offset="1" stop-color="#13202f"/>
          </linearGradient>
          <linearGradient id="wfFill3" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#1c2d2a"/>
            <stop offset="1" stop-color="#0e1f1c"/>
          </linearGradient>
        </defs>

        <!-- Stage 1: Sources -->
        <g class="wf-stage">
          <rect x="20" y="40" width="180" height="200" rx="12" fill="url(#wfFill1)" stroke="#2a3f5e" stroke-width="1.4"/>
          <text x="110" y="68" text-anchor="middle" fill="#5fb6ff" font-size="13" font-weight="700">1. SOURCES</text>
          <text x="35" y="92" fill="#cfd6e3" font-size="11">• The Hacker News</text>
          <text x="35" y="110" fill="#cfd6e3" font-size="11">• BleepingComputer</text>
          <text x="35" y="128" fill="#cfd6e3" font-size="11">• Microsoft Security Blog</text>
          <text x="35" y="146" fill="#cfd6e3" font-size="11">• Cyber Security News</text>
          <text x="35" y="168" fill="#36e0c0" font-size="11">• Cisco Talos</text>
          <text x="35" y="186" fill="#36e0c0" font-size="11">• Securelist (Kaspersky)</text>
          <text x="35" y="204" fill="#36e0c0" font-size="11">• SentinelLabs</text>
          <text x="35" y="222" fill="#36e0c0" font-size="11">• Unit 42 · ESET · Lab52</text>
          <text x="35" y="240" fill="#9aa3b2" font-size="10.5">+ CISA KEV</text>
        </g>

        <!-- Stage 2: Ingest -->
        <g class="wf-stage">
          <rect x="240" y="40" width="200" height="200" rx="12" fill="url(#wfFill1)" stroke="#2a3f5e" stroke-width="1.4"/>
          <text x="340" y="68" text-anchor="middle" fill="#5fb6ff" font-size="13" font-weight="700">2. INGEST</text>
          <text x="255" y="100" fill="#cfd6e3" font-size="11" font-weight="600">RSS / KEV JSON</text>
          <text x="255" y="120" fill="#9aa3b2" font-size="10.5">→ feedparser pulls entries</text>
          <text x="255" y="138" fill="#9aa3b2" font-size="10.5">→ 365-day rolling window</text>
          <text x="255" y="160" fill="#cfd6e3" font-size="11" font-weight="600">Full body fetch</text>
          <text x="255" y="180" fill="#9aa3b2" font-size="10.5">→ HTTPS GET with cache</text>
          <text x="255" y="198" fill="#9aa3b2" font-size="10.5">→ HTML→text + noise strip</text>
          <text x="255" y="216" fill="#cfd6e3" font-size="11" font-weight="600">Cross-source dedupe</text>
          <text x="255" y="234" fill="#9aa3b2" font-size="10.5">→ Jaccard ≥ 0.55 on titles</text>
        </g>

        <!-- Stage 3: Extraction -->
        <g class="wf-stage">
          <rect x="480" y="40" width="220" height="200" rx="12" fill="url(#wfFill2)" stroke="#3a2a5a" stroke-width="1.4"/>
          <text x="590" y="68" text-anchor="middle" fill="#b48dff" font-size="13" font-weight="700">3. EXTRACT</text>
          <text x="495" y="100" fill="#cfd6e3" font-size="11" font-weight="600">High-fidelity IOCs</text>
          <text x="495" y="120" fill="#9aa3b2" font-size="10.5">CVEs (regex)</text>
          <text x="495" y="138" fill="#9aa3b2" font-size="10.5">Hashes MD5/SHA1/SHA256</text>
          <text x="495" y="156" fill="#9aa3b2" font-size="10.5">Defanged IPs / domains</text>
          <text x="495" y="174" fill="#9aa3b2" font-size="10.5">hxxps:// URLs</text>
          <text x="495" y="196" fill="#cfd6e3" font-size="11" font-weight="600">Article mechanics</text>
          <text x="495" y="214" fill="#9aa3b2" font-size="10.5">Binaries / paths / cmd flags</text>
          <text x="495" y="230" fill="#9aa3b2" font-size="10.5">Registry / persistence keys</text>
        </g>

        <!-- Stage 4: Use cases -->
        <g class="wf-stage">
          <rect x="740" y="40" width="240" height="200" rx="12" fill="url(#wfFill2)" stroke="#3a2a5a" stroke-width="1.4"/>
          <text x="860" y="68" text-anchor="middle" fill="#b48dff" font-size="13" font-weight="700">4. USE CASES</text>
          <text x="755" y="100" fill="#cfd6e3" font-size="11" font-weight="600">Rule matching</text>
          <text x="755" y="120" fill="#9aa3b2" font-size="10.5">→ keyword triggers fire UC</text>
          <text x="755" y="142" fill="#cfd6e3" font-size="11" font-weight="600">Bespoke generation</text>
          <text x="755" y="162" fill="#9aa3b2" font-size="10.5">→ SPL/KQL hunts THIS</text>
          <text x="755" y="180" fill="#9aa3b2" font-size="10.5">  attack's specific bins/paths</text>
          <text x="755" y="200" fill="#cfd6e3" font-size="11" font-weight="600">IOC-driven hunts</text>
          <text x="755" y="220" fill="#9aa3b2" font-size="10.5">→ shared template + IOC list</text>
        </g>

        <!-- Stage 5: Outputs -->
        <g class="wf-stage">
          <rect x="1020" y="40" width="240" height="200" rx="12" fill="url(#wfFill3)" stroke="#2a5a4f" stroke-width="1.4"/>
          <text x="1140" y="68" text-anchor="middle" fill="#36e0c0" font-size="13" font-weight="700">5. OUTPUTS</text>
          <text x="1035" y="100" fill="#cfd6e3" font-size="11" font-weight="600">Articles tab</text>
          <text x="1035" y="118" fill="#9aa3b2" font-size="10.5">→ per-article cards + briefings</text>
          <text x="1035" y="138" fill="#cfd6e3" font-size="11" font-weight="600">ATT&amp;CK Matrix</text>
          <text x="1035" y="156" fill="#9aa3b2" font-size="10.5">→ 691 techniques × 2,236 UCs</text>
          <text x="1035" y="176" fill="#cfd6e3" font-size="11" font-weight="600">Threat Intel</text>
          <text x="1035" y="194" fill="#9aa3b2" font-size="10.5">→ CSV / JSON / STIX / RSS</text>
          <text x="1035" y="214" fill="#cfd6e3" font-size="11" font-weight="600">Briefings (markdown)</text>
          <text x="1035" y="232" fill="#9aa3b2" font-size="10.5">→ analyst-curated overlays</text>
        </g>

        <!-- Connectors -->
        <line x1="200" y1="140" x2="240" y2="140" stroke="#5fb6ff" stroke-width="2" marker-end="url(#wfArrow)"/>
        <line x1="440" y1="140" x2="480" y2="140" stroke="#5fb6ff" stroke-width="2" marker-end="url(#wfArrow)"/>
        <line x1="700" y1="140" x2="740" y2="140" stroke="#5fb6ff" stroke-width="2" marker-end="url(#wfArrow)"/>
        <line x1="980" y1="140" x2="1020" y2="140" stroke="#5fb6ff" stroke-width="2" marker-end="url(#wfArrow)"/>

        <!-- Bottom rail: analyst loop -->
        <g class="wf-loop">
          <rect x="20" y="320" width="1240" height="100" rx="12" fill="rgba(255,176,96,0.06)" stroke="#5a4a2a" stroke-width="1.4" stroke-dasharray="4 4"/>
          <text x="640" y="350" text-anchor="middle" fill="#ffb060" font-size="13" font-weight="700">Analyst loop (continuous)</text>
          <text x="100" y="378" fill="#cfd6e3" font-size="11">📖 Read article →</text>
          <text x="280" y="378" fill="#cfd6e3" font-size="11">✏ Curate briefing &lt;!-- curated:true --&gt; →</text>
          <text x="600" y="378" fill="#cfd6e3" font-size="11">🛠 Tune triggers / write new YAML UC →</text>
          <text x="950" y="378" fill="#cfd6e3" font-size="11">💾 Commit → next pipeline run picks up</text>
          <text x="640" y="402" text-anchor="middle" fill="#9aa3b2" font-size="10.5">Curated briefings get the &lt;!-- curated:true --&gt; marker and are preserved across runs.</text>
        </g>

        <line x1="640" y1="240" x2="640" y2="320" stroke="#ffb060" stroke-width="2" stroke-dasharray="4 4" marker-end="url(#wfArrow)"/>
      </svg>
    </div>

    <!-- ============== DETAILED STEPS ============== -->
    <h3 class="wf-section-title">1. Sources</h3>
    <div class="wf-step">
      <p>The pipeline pulls from <strong>11 feeds</strong> on every run:</p>
      <ul>
        <li><strong>News</strong> — The Hacker News, BleepingComputer, Microsoft Security Blog, Cyber Security News. Broad coverage, light on technical IOC tables.</li>
        <li><strong>IOC-rich vendor research</strong> — Cisco Talos, Securelist (Kaspersky), SentinelLabs, Unit 42 (Palo Alto), ESET WeLiveSecurity, Lab52 (S2 Grupo). Where the hash / IP / domain tables and APT write-ups live.</li>
        <li><strong>CISA KEV</strong> — authoritative exploited-vulnerability feed (JSON, not RSS).</li>
      </ul>
      <p>Adding a source is a 3-line entry in <code>SOURCES</code>. The fetcher detects RSS vs JSON automatically.</p>
    </div>

    <h3 class="wf-section-title">2. Ingest</h3>
    <div class="wf-step">
      <p>For each entry in the rolling <strong>365-day window</strong>:</p>
      <ol>
        <li><code>feedparser.parse()</code> reads the RSS preview.</li>
        <li><code>_fetch_full_body(url)</code> issues an HTTPS GET with a polite <code>User-Agent</code>, caches the HTML to <code>intel/.article_cache/</code>, and converts to plain text. <strong>Without this step the IOC feed only has CVEs</strong> — RSS previews don't include hash tables.</li>
        <li>Cross-source <strong>Jaccard dedupe</strong> on title token sets (threshold 0.55) merges "Chinese Silk Typhoon hacker extradited" (THN) with "Alleged Silk Typhoon hacker extradited" (BleepingComputer) into a single entry with two source attributions.</li>
      </ol>
    </div>

    <h3 class="wf-section-title">3. Extract</h3>
    <div class="wf-step">
      <p>Two parallel extractors run on every article body:</p>
      <p><strong>High-fidelity IOCs</strong> (<code>extract_indicators</code>):</p>
      <ul>
        <li>CVE — <code>CVE-\d{4}-\d{4,7}</code> regex.</li>
        <li>SHA256 / SHA1 / MD5 — fixed-width hex regexes.</li>
        <li>IPs / domains — <strong>defanged-only</strong>: <code>1[.]2[.]3[.]4</code>, <code>evil[.]com</code>, <code>hxxps://...</code>. Plain-text mentions are rejected because they're almost always the victim or platform, not the attacker.</li>
      </ul>
      <p><strong>Article mechanics</strong> (<code>extract_mechanics</code>):</p>
      <ul>
        <li>Binaries: regex on <code>*.exe / .dll / .sys / .ps1 / .vbs / ...</code> filtered through a noise list (chrome.exe, cmd.exe, etc.).</li>
        <li>Windows paths: <code>C:\</code> / <code>%APPDATA%</code> / <code>\Users\</code> / <code>\System32\</code> patterns, generic top-level paths filtered out.</li>
        <li>Unix paths: <code>/tmp</code>, <code>/var</code>, <code>/Library</code>, <code>/etc</code> patterns.</li>
        <li>Registry keys: <code>HK[LCU][MR]?\...</code> patterns.</li>
        <li>Persistence keywords ("scheduled task", "launchagent", "run key", etc.) → linked to MITRE technique IDs.</li>
        <li>Command-line fragments — <code>-EncodedCommand</code>, <code>FromBase64String</code>, <code>vssadmin delete shadows</code>, etc.</li>
      </ul>
    </div>

    <h3 class="wf-section-title">4. Use cases</h3>
    <div class="wf-step">
      <p>Three classes of use case fire per article:</p>
      <p><strong>(a) Rule-fired generic UCs</strong> — <code>rules/*.yml</code> contain trigger keyword lists. If the article body matches any trigger, the rule's pre-built use case (in <code>use_cases/*.yml</code>) is added to the briefing. Example: any article mentioning "psexec" fires <code>UC_LATERAL_PSEXEC</code>.</p>
      <p><strong>(b) Bespoke article-specific UCs</strong> — <em>new this session</em>. <code>extract_mechanics</code> output drives <code>_make_bespoke_uc</code>, which assembles a per-article SPL+KQL searching for the <strong>actual binaries / paths / commandline fragments</strong> named in the article. Threshold: at least one mechanic anchor must be present, otherwise no bespoke UC is emitted (silence beats noise).</p>
      <p><strong>(c) IOC-substitution UCs</strong> — when the article has a CVE / IP / domain / hash, the matching boilerplate UC fires with the actual IOC list substituted in. Canonical SPL/KQL bodies live once in <a href="briefings/_TEMPLATES.md">briefings/_TEMPLATES.md</a>; the briefing inlines only the IOC values.</p>
    </div>

    <h3 class="wf-section-title">5. Outputs</h3>
    <div class="wf-step">
      <ul>
        <li><strong>Articles tab</strong> — per-article cards (this <code>index.html</code>) + per-article markdown briefings under <code>briefings/&lt;date&gt;/</code>.</li>
        <li><strong>ATT&amp;CK Matrix tab</strong> — 14 tactics × 691 techniques. Coverage drawn from 23 internal UCs + <strong>2,213 synced Splunk ESCU detections</strong>. Click any technique cell, then any UC card to expand it inline with full SPL/KQL — backed by <code>catalog/use_cases_full.js</code>.</li>
        <li><strong>Threat Intel tab</strong> — IOC feed exports: CSV, JSON, STIX 2.1, RSS, Splunk lookup. Aggregated across every article in the window with source attribution.</li>
      </ul>
      <p>All outputs commit to <a href="https://github.com/Virtualhaggis/usecaseintel">github.com/Virtualhaggis/usecaseintel</a>; <code>run_daily.bat</code> runs validate → generate → digest → auto-commit on a schedule.</p>
    </div>

    <h3 class="wf-section-title">LLM-driven UC generation (opt-in)</h3>
    <div class="wf-step">
      <p>When <code>ANTHROPIC_API_KEY</code> is set in the environment, the pipeline sends each article body to an LLM with a structured detection-engineer prompt, parses the response as JSON, validates the techniques (<code>T####.###</code> format) + tier (alerting/hunting) + KQL/SPL fields, and emits the resulting UseCase objects alongside the regex bespoke UCs.</p>
      <p>The LLM is told: use the actual binaries/paths/cmdlines named in the article, not invented ones; if the article describes the attack only narratively, return no UCs. Output is cached per article URL hash so repeat runs cost nothing.</p>
      <p>Model: <code>claude-opus-4-7</code> by default for top-shelf detection quality (configurable via <code>USECASEINTEL_LLM_MODEL</code> — set to <code>claude-haiku-4-5-20251001</code> for a budget run). The first comprehensive run hits the LLM for every article that passes the attack-content filter; subsequent runs only re-analyse articles whose body has changed in the last 24 hours or that have new similar peers, so steady-state cost is small.</p>
      <p>Each LLM-emitted UC is title-prefixed <code>[LLM]</code> and shows up in the matrix drawer alongside the rule-fired and regex-bespoke variants. Failures (no API key, parse error, network timeout) are logged but never fail the pipeline.</p>
    </div>

    <h3 class="wf-section-title">IOC enrichment (opt-in)</h3>
    <div class="wf-step">
      <p>When <code>ABUSECH_API_KEY</code> is set, every IOC in <code>intel/iocs.csv</code> is cross-referenced against:</p>
      <ul>
        <li><strong>ThreatFox (abuse.ch)</strong> — malware family attribution + first-seen + reporter for IPs / domains / hashes / CVEs / URLs.</li>
        <li><strong>URLhaus (abuse.ch)</strong> — URL counts + blacklist memberships for hosts.</li>
      </ul>
      <p>Free auth keys at <a href="https://auth.abuse.ch/" target="_blank" rel="noopener">auth.abuse.ch</a> — abuse.ch added auth in 2024-2025 to control abuse. New CSV columns: <code>threatfox_malware</code>, <code>threatfox_threat_type</code>, <code>urlhaus_url_count</code>, <code>urlhaus_blacklists</code>, <code>enrichment_url</code>. Cache lives in <code>intel/.enrich_cache/</code>; if no key is set the columns stay blank and the pipeline runs unchanged.</p>
      <p>Practical impact when enabled: an IOC the SOC sees in our feed is flanked by "is this on abuse.ch's known-bad list and what malware family is it linked to?" — turning a list of values into intel with attribution.</p>
    </div>

    <h3 class="wf-section-title">Per-platform rule packs</h3>
    <div class="wf-step">
      <p>Every internal UC is now exported to multiple SIEM-native formats under <code>rule_packs/</code>:</p>
      <ul>
        <li><code>splunk/savedsearches.conf</code> — drop-in Splunk app config. Each saved search is <code>enableSched = 0</code> by default — review-then-enable.</li>
        <li><code>sentinel/&lt;uc&gt;.json</code> — Microsoft Sentinel ARM analytics rule template.</li>
        <li><code>elastic/&lt;uc&gt;.json</code> — Elastic detection rule (KQL embedded in note for analyst port-over to ECS/EQL).</li>
        <li><code>sigma/&lt;uc&gt;.yml</code> — Sigma format. Convert with <code>sigma-cli</code> to your SIEM dialect.</li>
      </ul>
      <p>All exports tier-aware: alerting runs hourly, hunting runs daily; severity high vs low; tier + fp_rate + MITRE attached to custom-details.</p>
    </div>

    <h3 class="wf-section-title">Quality gates — tier &amp; IOC allowlist</h3>
    <div class="wf-step">
      <p>Two filters keep the output honest:</p>
      <p><strong>UC tier — alerting vs hunting.</strong> Every use case is tagged:</p>
      <ul>
        <li><strong style="color:var(--good);">ALERTING</strong> — high-fidelity. Specific IOCs, threshold or temporal correlation (<code>between (T .. T+60s)</code>), named-binary hunt, anomaly logic. Safe to wire to a SIEM rule with normal triage SLA.</li>
        <li><strong style="color:var(--warn);">HUNTING</strong> — starter content. Returns rows that need analyst review; will produce false positives without environment tuning. Use as a hunt query first; promote to alerting after baselining + adding suppression for legitimate use.</li>
      </ul>
      <p>How it's set: explicit <code>tier:</code> field in the UC YAML wins. Otherwise <code>_infer_tier_from_query()</code> looks for alerting signals (temporal joins, thresholds, named-binary <code>IN</code>-lists, anomaly stats) and defaults to hunting if none are present. Splunk ESCU detections inherit tier from the upstream <code>type</code> — TTP/Correlation → alerting, Anomaly/Hunting → hunting. Bespoke article-generated UCs default to hunting.</p>
      <p>Filter the drawer by tier (Alerting / Hunting) using the dropdown in the Use cases mapped section.</p>

      <p style="margin-top:14px;"><strong>IOC allowlist — drop platform / reserved infrastructure.</strong> No SOC wants <code>google.com</code> or <code>192.168.0.1</code> in their block list. <code>_ioc_is_known_safe()</code> drops:</p>
      <ul>
        <li>Mainstream platform domains (Google, Microsoft, Apple, Amazon, Cloudflare, GitHub, npm, PyPI, Docker Hub, Wikipedia, Stack Overflow, social platforms).</li>
        <li>Security-vendor self-references (THN, BleepingComputer, Talos, Securelist, etc.).</li>
        <li>Common dead-drop dispensers (pastebin, ghostbin) — which CAN be abused but should be hunted manually rather than block-listed.</li>
        <li>Reserved IPv4 ranges: RFC1918 (<code>10/8</code>, <code>172.16/12</code>, <code>192.168/16</code>), loopback (<code>127/8</code>), link-local (<code>169.254/16</code>), TEST-NETs, multicast.</li>
        <li>Public DNS providers (<code>8.8.8.8</code>, <code>1.1.1.1</code>, etc.).</li>
      </ul>
      <p>Internal IPs aren't useless — they're just useless <em>standalone</em>. A bespoke UC describing lateral movement <em>can</em> reference them as part of a broader chain, but they don't belong in the IOC feed where the value is "block this on the perimeter".</p>
    </div>

    <h3 class="wf-section-title">Analyst loop</h3>
    <div class="wf-step">
      <p>Curated briefings get a <code>&lt;!-- curated:true --&gt;</code> HTML comment as line 1. The briefing writer skips any file with that marker so analyst overlays are preserved across pipeline runs. The pattern:</p>
      <ol>
        <li>Pipeline emits an auto-generated briefing.</li>
        <li>Analyst reads the article, rewrites the briefing with attribution / actor context / sector implications / bespoke detection logic, adds <code>&lt;!-- curated:true --&gt;</code>.</li>
        <li>Commits. Future pipeline runs see the marker and leave the file alone.</li>
      </ol>
      <p>For new use cases the analyst writes a YAML file under <code>use_cases/&lt;phase&gt;/UC_X.yml</code>; the loader at module-load time auto-registers it and the matrix builder picks it up on the next run.</p>
    </div>

    <h3 class="wf-section-title">Commands cheat-sheet</h3>
    <div class="wf-step">
      <pre style="background:var(--panel-elev);border:1px solid var(--border);border-radius:6px;padding:14px;font-size:12px;overflow:auto;">
# Daily run (Windows)
run_daily.bat                                   # validate → generate → digest → auto-commit

# Manual one-shot
python validate.py                              # YAML schema + SPL/KQL field checks
python generate.py                              # rebuild index.html + intel/ + briefings/
python digest.py                                # daily_digest.md summary

# Disable body fetch (offline / debug)
THN_FETCH_FULL_BODY=0 python generate.py        # IOC feed loses hash/IP/domain coverage
THN_FETCH_DELAY=0.1 python generate.py          # speed up (less polite to sources)
      </pre>
    </div>
  </div>
</div>

<div id="view-about" class="view">
  <div class="workflow-wrap" style="max-width:1180px;">
    <h2 class="wf-title" style="font-size:28px;">About Clankerusecase</h2>
    <p class="wf-lede" style="font-size:15px;max-width:760px;">
      Detection content for SOC analysts, generated from threat-intel articles
      the day they break. Free, open-source, and community-shaped.
    </p>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">What this is</h3>
      <p>
        Clankerusecase reads recent threat-intel articles (The Hacker News,
        BleepingComputer, Microsoft Security Blog, Cisco Talos, Securelist,
        SentinelLabs, Unit 42, ESET, Lab52, Cyber Security News, CISA KEV) and produces detection use
        cases an analyst can drop into their SIEM. Every use case is mapped
        to MITRE ATT&amp;CK, tagged with a tier (alerting vs hunting) and
        a false-positive estimate, and — for the article-bespoke ones —
        written by an LLM that's actually <em>read</em> the article rather
        than spat out a generic technique template.
      </p>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">The goal</h3>
      <ul style="line-height:1.6;">
        <li><strong>Hand analysts ready-to-run detection content</strong> the
            day a campaign breaks — not three weeks later when the vendor
            blog post has been turned into a "rule pack" behind a paywall.</li>
        <li><strong>Cover the platforms analysts actually use.</strong>
            Pick a vendor, get the same detection rendered for it.</li>
        <li><strong>Be community-driven.</strong> The platforms covered, the
            tier thresholds, the FP estimates, the per-source filters — all
            decided by people doing detection engineering and threat hunting
            day-to-day, not by a marketing team.</li>
      </ul>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">Platform coverage today</h3>
      <table class="wf-table">
        <thead><tr><th>Platform</th><th>Status</th><th>Notes</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>Microsoft Defender</strong> (Advanced Hunting / KQL)</td>
            <td><span class="pill tier-alerting" style="background:rgba(34,197,94,.15);color:#86efac;border:1px solid rgba(34,197,94,.4);padding:2px 8px;border-radius:4px;font-size:11px;">Working well</span></td>
            <td>Every use case has a hand-checked KQL query against the
                <code>DeviceProcessEvents</code> / <code>EmailEvents</code> /
                <code>UrlClickEvents</code> / <code>AADSignInEventsBeta</code>
                tables. Pre-deployed table validation against the Defender
                schema. This is the most mature path on the site today.</td>
          </tr>
          <tr>
            <td><strong>Splunk</strong> (CIM / ESCU)</td>
            <td><span class="pill" style="background:rgba(234,179,8,.15);color:#fde047;border:1px solid rgba(234,179,8,.4);padding:2px 8px;border-radius:4px;font-size:11px;">In progress</span></td>
            <td>SPL queries emitted against <code>Endpoint</code>,
                <code>Network_Traffic</code>, <code>Email</code>,
                <code>Vulnerabilities</code>, <code>Web</code> data models;
                CIM-validated. 2,200+ Splunk ESCU detections synced into the
                ATT&amp;CK matrix. Field-level tuning for production deployment
                is the next focus area.</td>
          </tr>
          <tr>
            <td><strong>Sentinel ARM / Elastic / Sigma</strong></td>
            <td><span class="pill" style="background:rgba(148,163,184,.15);color:#cbd5e1;border:1px solid rgba(148,163,184,.4);padding:2px 8px;border-radius:4px;font-size:11px;">Rule-pack export</span></td>
            <td>Rule packs are emitted to <code>rule_packs/</code> on every
                build (all <code>enabled=false</code> by default — read,
                review, then enable). Validation against each platform's
                native schema is on the roadmap.</td>
          </tr>
          <tr>
            <td><strong>Anything else?</strong></td>
            <td><span class="pill" style="background:rgba(125,211,252,.15);color:#7dd3fc;border:1px solid rgba(125,211,252,.4);padding:2px 8px;border-radius:4px;font-size:11px;">Tell us</span></td>
            <td>CrowdStrike NG-SIEM? Chronicle / Google SecOps? Sumo? OpenSearch?
                Drop a request in Discord (link below) and if there's interest
                from the community we'll wire it in.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">Community &amp; Discord</h3>
      <p>
        We're spinning up a Discord for analysts and detection engineers
        using the site. The space is for:
      </p>
      <ul style="line-height:1.6;">
        <li>Suggesting new platforms to add (KQL → SPL is done; what's next?).</li>
        <li>Sharing tuning notes for the FP rate on specific use cases in
            your environment.</li>
        <li>Flagging articles you'd like covered (the feed-fetcher is fast
            but not exhaustive — analyst-curated tips help).</li>
        <li>Posting your own detection ideas — if they fit the site's
            criteria they'll get added with attribution.</li>
      </ul>
      <div id="discord-cta" style="margin-top:14px;padding:14px 16px;background:rgba(88,101,242,.08);border:1px solid rgba(88,101,242,.3);border-radius:8px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
        <div style="font-size:24px;">💬</div>
        <div style="flex:1;min-width:200px;">
          <div style="font-weight:600;color:var(--text);margin-bottom:2px;">Join the Clankerusecase Discord</div>
          <div style="color:var(--muted);font-size:13px;">Detection engineers, threat hunters, SOC analysts — all welcome.</div>
        </div>
        <a id="discord-link" href="https://discord.gg/6KSXVrC3Kr" target="_blank" rel="noopener"
           style="padding:8px 16px;background:#5865f2;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;font-size:13px;">
          Open Discord →
        </a>
      </div>
      <p style="font-size:12px;color:var(--muted-2);margin-top:8px;">
        <em>Permanent invite:</em>
        <a href="https://discord.gg/6KSXVrC3Kr" target="_blank" rel="noopener"
           style="color:var(--accent);font-family:var(--mono);">https://discord.gg/6KSXVrC3Kr</a>
        — never expires, no member cap. Channels: <code>#welcome</code>,
        <code>#use-case-requests</code>, <code>#platform-requests</code>,
        <code>#detection-engineering</code>, <code>#threat-hunting</code>,
        <code>#site-feedback</code>. Verified-email + AutoMod spam protection
        on by default.
      </p>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">How a use case lands here</h3>
      <ol style="line-height:1.7;">
        <li>Article published by a covered intel source.</li>
        <li>Pipeline fetches the full body (not just the RSS preview), pulls
            IOCs (defanged-aware, with allowlists for legitimate platforms),
            and infers MITRE techniques from narrative keywords.</li>
        <li>Rule-fired generic UCs from <code>use_cases/*.yml</code> attach
            based on trigger keywords.</li>
        <li>An LLM (your Claude Code OAuth session, or an
            <code>ANTHROPIC_API_KEY</code>) reads the article body and
            generates 1–3 <em>article-specific</em> bespoke UCs with their
            own SPL/KQL — these get the <code>[LLM]</code> prefix and sort
            to the top of every list because they're the highest-fidelity
            detection content on the page.</li>
        <li>WebSearch corroboration: the LLM cross-checks vendor advisories
            (Microsoft Threat Intel, Mandiant, CrowdStrike, MITRE, abuse.ch)
            and links them in the briefing as <em>"Cross-checked against:"</em>.</li>
        <li>Validation pass: every SPL field is checked against the CIM spec
            and ESCU production references; every KQL table/column against
            the Defender schema. Fail validation → don't ship.</li>
      </ol>
      <p style="font-size:12.5px;color:var(--muted);margin-top:8px;">
        See the <strong>Workflow</strong> tab for the full diagram and
        per-stage prompt detail.
      </p>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">Repo &amp; licence</h3>
      <p>
        Source:
        <a href="https://github.com/Virtualhaggis/usecaseintel" target="_blank" style="color:var(--accent);">github.com/Virtualhaggis/usecaseintel</a>.
        MIT-licensed. Contributions welcome — open an issue or PR. The site
        is rebuilt by <code>generate.py</code> on every run; the catalog
        lives in <code>catalog/use_cases_full.json</code> for non-browser
        consumers (TIPs, scripts, your SIEM's API).
      </p>
    </div>
  </div>
</div>

<footer>
  Splunk SPL conforms to the <a href="https://help.splunk.com/en/data-management/common-information-model/8.5/introduction/overview-of-the-splunk-common-information-model" style="color:var(--accent);" target="_blank">Splunk Common Information Model (CIM)</a> — uses
  <code>tstats</code> against accelerated data models with the canonical <code>Processes.dest</code>,
  <code>All_Email.recipient</code>, <code>All_Traffic.dest</code> field paths.
  Macros: <code>`summariesonly`</code> · <code>`drop_dm_object_name()`</code> · <code>`security_content_ctime()`</code> ship with Splunk ESCU.
  <br>Defender KQL targets <a href="https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables" style="color:var(--accent);" target="_blank">Advanced Hunting schema</a>.
  Kill chain follows the Lockheed Martin 7-phase model.
</footer>

<!-- Per-UC detail sidecar. Sets window.__UC_DETAILS__ = { ucId: {...} }
     so clicking a UC card in the matrix drawer can render full SPL/KQL.
     Loaded async; the drawer code handles the case where it hasn't arrived. -->
<script src="catalog/use_cases_full.js" async></script>

<script>
// ----- Tab switching --------------------------------------------------
document.addEventListener('click', e => {
  const btn = e.target.closest('.tab-btn');
  if (!btn) return;
  const parent = btn.closest('.uc-body, .killchain, article.card');
  if (!parent) return;
  parent.querySelectorAll(':scope > .tabs > .tab-btn, :scope .tabs > .tab-btn').forEach(b => {
    if (b.closest('.uc-body, .killchain, article.card') === parent) b.classList.remove('active');
  });
  parent.querySelectorAll(':scope > .tab-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  const tgt = parent.querySelector('#' + btn.dataset.target);
  if (tgt) tgt.classList.add('active');
});

// ----- Splunk SPL Summarised / Non-summarised toggle -------------------
// The SPL pane on tstats-based UCs renders both an accelerated body
// (summariesonly=true via the macro) and an auto-derived non-accelerated
// body (summariesonly=false). The user toggles between them; persists
// nothing — every UC defaults to "Summarised" on page load.
//
// Scoped via .spl-toggle-group so the same handler works for both the
// article-card surface and the Library drawer surface (different parent
// containers, same toggle pattern).
document.addEventListener('click', e => {
  const btn = e.target.closest('.spl-mode-btn');
  if (!btn) return;
  const parent = btn.closest('.spl-toggle-group') || btn.closest('.tab-content');
  if (!parent) return;
  parent.querySelectorAll('.spl-mode-btn').forEach(b => b.classList.toggle('active', b === btn));
  parent.querySelectorAll('.spl-mode-body').forEach(p => {
    p.classList.toggle('active', p.id === btn.dataset.target);
  });
});

// JS port of generate.py:_spl_make_unsummarised — used by the Library
// drawer to compute the non-accelerated variant of an SPL query without
// needing it pre-rendered.
function _splUnsummarised(spl) {
  if (!spl || !/tstats/i.test(spl)) return spl;
  let out = spl;
  out = out.replace(/`summariesonly`/g, 'summariesonly=false');
  out = out.replace(/\bsummariesonly\s*=\s*(?:true|t|1|yes|y)\b/gi, 'summariesonly=false');
  if (!/\bsummariesonly\s*=/i.test(out)) {
    out = out.replace(/(\|\s*tstats\b)(\s+)/i, '$1 summariesonly=false$2');
  }
  return out;
}

// ----- Toggle kill chain ----------------------------------------------
document.querySelectorAll('.btn[data-target]').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    if (!target) return;
    target.classList.toggle('active');
    btn.classList.toggle('primary');
    const lbl = btn.querySelector('.kc-label');
    if (lbl) lbl.textContent = target.classList.contains('active') ? 'Hide kill chain' : 'Show kill chain';
  });
});

// ----- Copy code block ------------------------------------------------
document.addEventListener('click', e => {
  const btn = e.target.closest('.copy-btn');
  if (!btn) return;
  e.stopPropagation();
  const code = btn.parentElement.querySelector('code').innerText;
  navigator.clipboard.writeText(code).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1300);
  });
});

// ----- Active nav highlighting on scroll ------------------------------
const navItems = document.querySelectorAll('#navlist .nav-item');
const cards = document.querySelectorAll('article.card');
// During programmatic scroll (nav click) the IntersectionObserver fires for
// every article the viewport passes through, which lands the "active" state
// on the next short card. Suspend the observer briefly during click-driven
// scrolls so the explicit click always wins.
let scrollLockUntil = 0;
const observer = new IntersectionObserver(entries => {
  if (Date.now() < scrollLockUntil) return;
  entries.forEach(en => {
    if (en.isIntersecting) {
      navItems.forEach(n => n.classList.remove('active'));
      const el = document.querySelector(`#navlist .nav-item[data-jump="${en.target.id}"]`);
      if (el) el.classList.add('active');
    }
  });
}, { rootMargin: '-30% 0px -55% 0px' });
cards.forEach(c => observer.observe(c));

// ----- Nav click jumps -----------------------------------------------
// content-visibility:auto on article cards means offscreen cards
// contribute only their `contain-intrinsic-size` (720px) to layout
// until they actually render. scrollIntoView calculates the target's
// position using those 720px placeholders, but as smooth-scroll passes
// through each card it materialises at its real height (often 1.5-3k px),
// pushing the target further down — so the scroll lands several cards
// short. Helper: force-render every card in the strip between current
// scroll and target BEFORE scrolling, so layout offsets are accurate
// and scrollIntoView lands on the right card first try.
function scrollToArticleAccurate(target, block) {
  if (!target) return;
  const currentY = window.scrollY;
  const estTargetY = target.getBoundingClientRect().top + currentY;
  const lo = Math.min(currentY, estTargetY) - 200;
  const hi = Math.max(currentY, estTargetY) + window.innerHeight + 200;
  cards.forEach(c => {
    const r = c.getBoundingClientRect();
    const top = r.top + currentY;
    if (top + r.height >= lo && top <= hi) {
      c.style.contentVisibility = 'visible';
    }
  });
  // Synchronous layout flush so the now-rendered cards contribute their
  // real heights before scrollIntoView reads offsets.
  void document.body.offsetHeight;
  target.scrollIntoView({behavior:'smooth', block: block || 'start'});
}

navItems.forEach(item => {
  item.addEventListener('click', () => {
    const id = item.dataset.jump;
    const target = document.getElementById(id);
    if (!target) return;
    // Set the active state immediately and lock the observer for ~700ms
    // so the smooth-scroll animation can't re-flip it to the next card.
    navItems.forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    scrollLockUntil = Date.now() + 700;
    scrollToArticleAccurate(target, 'start');
  });
});

// ----- Filter chips: phase, severity ----------------------------------
const activeFilters = { phase: null, sev: null, tech: null };
function applyFilters() {
  cards.forEach(c => {
    const phases = (c.dataset.phases || '').split(',');
    const sev = c.dataset.sev || '';
    const techs = (c.dataset.techs || '').split(',');
    let show = true;
    if (activeFilters.phase && !phases.includes(activeFilters.phase)) show = false;
    if (activeFilters.sev && sev !== activeFilters.sev) show = false;
    if (activeFilters.tech && !techs.includes(activeFilters.tech)) show = false;
    c.classList.toggle('hidden', !show);
    const navEl = document.querySelector(`#navlist .nav-item[data-jump="${c.id}"]`);
    if (navEl) navEl.style.display = show ? '' : 'none';
  });
}
document.querySelectorAll('.fchip').forEach(chip => {
  chip.addEventListener('click', () => {
    const k = chip.dataset.key;
    const v = chip.dataset.val;
    if (activeFilters[k] === v) {
      activeFilters[k] = null;
      chip.classList.remove('on');
    } else {
      document.querySelectorAll(`.fchip[data-key="${k}"]`).forEach(c => c.classList.remove('on'));
      activeFilters[k] = v;
      chip.classList.add('on');
    }
    applyFilters();
  });
});

// ----- Click ATT&CK technique pill to filter -------------------------
document.addEventListener('click', e => {
  const t = e.target.closest('.ind.tech');
  if (!t) return;
  const tid = t.textContent.trim();
  if (activeFilters.tech === tid) {
    activeFilters.tech = null;
  } else {
    activeFilters.tech = tid;
  }
  applyFilters();
  // Highlight active filter visually:
  document.querySelectorAll('.ind.tech').forEach(el => {
    el.style.outline = (activeFilters.tech && el.textContent.trim() === activeFilters.tech) ? '2px solid var(--accent-3)' : 'none';
  });
});

// ----- Smart Ctrl/Cmd+K search palette -------------------------------
// Grouped fuzzy search across Use Cases, Articles, Techniques, Actors.
// Builds the index lazily on first open from MATRIX + DOM + window globals.
// Recent searches persisted in localStorage. Keyboard nav: ↑↓ Enter Esc.
const overlay = document.getElementById('searchOverlay');
const input = document.getElementById('searchInput');
const results = document.getElementById('searchResults');
const trigger = document.getElementById('searchTrigger');

const RECENT_KEY = 'usecaseintel:recent-searches';
const MAX_RECENT = 6;
const PER_GROUP_LIMIT = 8;

// --- Index build ---
let SEARCH_INDEX = null;

function _buildIndex() {
  const idx = { ucs: [], arts: [], techs: [], actors: [], targets: [] };

  // Use cases (from MATRIX) — primary searchable surface
  if (window.MATRIX && Array.isArray(MATRIX.ucs)) {
    MATRIX.ucs.forEach(uc => {
      const techs = (uc.techs || []).join(' ');
      const tgs = (uc.tg || []).join(' ');
      idx.ucs.push({
        kind: 'uc',
        title: uc.t || uc.n || '',
        meta: [uc.src || '', uc.ph || '', uc.tier || '', techs].filter(Boolean).join(' · '),
        techs: techs,
        blob: ((uc.t || '') + ' ' + (uc.n || '') + ' ' + techs + ' ' +
                (uc.ph || '') + ' ' + (uc.src || '') + ' ' + (uc.tier || '') + ' ' +
                tgs).toLowerCase(),
        ref: uc,
      });
    });
  }

  // Target surfaces — one synthetic entry per OS / cloud / SaaS so
  // "linux", "aws", "okta" etc surface the static landing page.
  const _TGT_INDEX = [
    ['windows','Windows','🪟'], ['linux','Linux','🐧'], ['macos','macOS','🍏'],
    ['aws','AWS','☁'], ['azure','Azure','⛅'], ['gcp','GCP','☁'],
    ['kubernetes','Kubernetes','⎈'], ['m365','Microsoft 365','📧'],
    ['okta','Okta','🔑'], ['vcs','Source control','🐙'],
    ['identity','Identity','👤'], ['web-app','Web App','🌐'],
  ];
  if (window.MATRIX && Array.isArray(MATRIX.ucs)) {
    const counts = {};
    MATRIX.ucs.forEach(uc => (uc.tg || []).forEach(t => { counts[t] = (counts[t]||0) + 1; }));
    _TGT_INDEX.forEach(([tag, label, icon]) => {
      const cnt = counts[tag] || 0;
      idx.targets.push({
        kind: 'target',
        tag, icon,
        title: label + ' detections',
        slug: tag,
        meta: cnt + (cnt === 1 ? ' use case' : ' use cases'),
        blob: (label + ' ' + tag + ' detections target surface').toLowerCase(),
      });
    });
  }

  // Articles — read from DOM data-attributes
  document.querySelectorAll('#view-articles article.card').forEach(c => {
    const title = c.querySelector('h2 a, h2')?.textContent?.trim() || c.id;
    const sources = c.dataset.sources || '';
    const techs = c.dataset.techs || '';
    const sev = c.dataset.sev || '';
    const search = c.dataset.search || '';
    idx.arts.push({
      kind: 'art',
      id: c.id,
      slug: c.dataset.artSlug || '',
      title: title,
      meta: [sev.toUpperCase(), sources.split('|')[0] || '', techs.split(',').slice(0, 3).join(', ')].filter(Boolean).join(' · '),
      blob: (title + ' ' + search + ' ' + sources + ' ' + techs).toLowerCase(),
      sev: sev,
    });
  });

  // Techniques (from MATRIX.techniques)
  if (window.MATRIX && MATRIX.techniques) {
    Object.entries(MATRIX.techniques).forEach(([tid, info]) => {
      const tactics = (info.tactics || []).join(', ');
      const ucCount = (MATRIX.tech_ucs && MATRIX.tech_ucs[tid] || []).length;
      const artCount = (MATRIX.tech_arts && MATRIX.tech_arts[tid] || []).length;
      idx.techs.push({
        kind: 'tech',
        tid: tid,
        title: tid + ' · ' + (info.name || ''),
        meta: [tactics, ucCount + ' UCs', artCount + ' arts'].filter(Boolean).join(' · '),
        blob: (tid + ' ' + (info.name || '') + ' ' + tactics).toLowerCase(),
      });
    });
  }

  // Actors — preferred source: window.__ACTORS__ (loaded by the actors tab),
  // fallback to scraping data-actor-name from the DOM if present.
  const actorList = (window.__ACTORS__ && Array.isArray(window.__ACTORS__)) ? window.__ACTORS__ : [];
  actorList.forEach(a => {
    const name = a.name || a.canonical || '';
    if (!name) return;
    const aliases = (a.aliases || []).join(', ');
    const country = a.country || '';
    idx.actors.push({
      kind: 'actor',
      title: name,
      slug: (a.slug || name).toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      meta: [country, aliases ? 'aka ' + aliases : '', (a.articles?.length || 0) + ' articles'].filter(Boolean).join(' · '),
      blob: (name + ' ' + aliases + ' ' + country).toLowerCase(),
    });
  });

  return idx;
}

// --- Scoring ---
// Substring + token-aligned match with a score boost for prefix hits and
// exact T-IDs / CVE matches.
function _score(blob, q) {
  if (!q) return 0;
  const i = blob.indexOf(q);
  if (i < 0) {
    // fall back to AND-on-tokens
    const toks = q.split(/\s+/).filter(Boolean);
    if (!toks.every(t => blob.includes(t))) return 0;
    return 50;  // weak match
  }
  // i === 0 is a prefix match — strongest
  if (i === 0) return 1000;
  // word-boundary prefix is next-best
  if (blob[i - 1] === ' ' || blob[i - 1] === '/' || blob[i - 1] === '.') return 800;
  return 500 - Math.min(i, 400);  // earlier-in-string is better
}

function _doSearch(q) {
  q = q.toLowerCase().trim();
  if (!SEARCH_INDEX) SEARCH_INDEX = _buildIndex();
  if (!q) return null;
  const out = { ucs: [], arts: [], techs: [], actors: [], targets: [] };
  ['ucs', 'arts', 'techs', 'actors', 'targets'].forEach(k => {
    SEARCH_INDEX[k].forEach(item => {
      const s = _score(item.blob, q);
      if (s > 0) out[k].push({ item, score: s });
    });
    out[k].sort((a, b) => b.score - a.score);
    out[k] = out[k].slice(0, PER_GROUP_LIMIT);
  });
  return out;
}

// --- Highlight matched substring ---
function _hl(text, q) {
  if (!q) return _escapeHtml(text);
  const lc = text.toLowerCase();
  const i = lc.indexOf(q.toLowerCase());
  if (i < 0) return _escapeHtml(text);
  return _escapeHtml(text.slice(0, i)) + '<mark>' + _escapeHtml(text.slice(i, i + q.length)) + '</mark>' + _escapeHtml(text.slice(i + q.length));
}
function _escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
}

// --- Recent searches ---
function _getRecent() {
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); }
  catch { return []; }
}
function _addRecent(q) {
  q = q.trim(); if (!q) return;
  let r = _getRecent().filter(x => x !== q);
  r.unshift(q);
  r = r.slice(0, MAX_RECENT);
  try { localStorage.setItem(RECENT_KEY, JSON.stringify(r)); } catch {}
}

// --- DOM render ---
let resultEls = [];
let selIndex = 0;

function openSearch() {
  overlay.classList.add('open');
  input.value = '';
  _renderEmpty();
  setTimeout(() => input.focus(), 30);
}
function closeSearch() { overlay.classList.remove('open'); }
trigger.addEventListener('click', openSearch);
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault(); openSearch();
  } else if (e.key === 'Escape' && overlay.classList.contains('open')) {
    closeSearch();
  } else if (overlay.classList.contains('open')) {
    if (e.key === 'ArrowDown') { e.preventDefault(); selIndex = Math.min(selIndex + 1, resultEls.length - 1); _refreshSel(); }
    else if (e.key === 'ArrowUp')   { e.preventDefault(); selIndex = Math.max(selIndex - 1, 0); _refreshSel(); }
    else if (e.key === 'Enter' && resultEls[selIndex]) {
      _addRecent(input.value);
      resultEls[selIndex].click();
    }
  }
});
overlay.addEventListener('click', e => { if (e.target === overlay) closeSearch(); });

function _refreshSel() {
  resultEls.forEach((el, i) => el.classList.toggle('sel', i === selIndex));
  resultEls[selIndex]?.scrollIntoView({ block: 'nearest' });
}

function _renderEmpty() {
  results.innerHTML = '';
  resultEls = [];
  selIndex = 0;
  const recent = _getRecent();
  if (recent.length) {
    const head = document.createElement('div');
    head.className = 'sr-group-head';
    head.innerHTML = 'Recent searches <span class="sr-group-count">' + recent.length + '</span>';
    results.appendChild(head);
    recent.forEach(q => {
      const div = document.createElement('div');
      div.className = 'search-result';
      div.innerHTML = '<div class="sr-icon">↻</div><div class="sr-body"><div class="sr-title">' + _escapeHtml(q) + '</div><div class="sr-meta">click to repeat</div></div>';
      div.addEventListener('click', () => { input.value = q; _renderResults(q); });
      results.appendChild(div);
      resultEls.push(div);
    });
  } else {
    const e = document.createElement('div');
    e.className = 'search-empty';
    e.textContent = 'Type to search use cases, articles, techniques (T1566), actors, CVEs…';
    results.appendChild(e);
  }
}

function _renderResults(q) {
  q = q.trim();
  if (!q) { _renderEmpty(); return; }

  const grouped = _doSearch(q);
  results.innerHTML = '';
  resultEls = [];
  selIndex = 0;
  if (!grouped) { _renderEmpty(); return; }

  const groups = [
    ['ucs',     'Use Cases',     'UC'],
    ['techs',   'Techniques',    'T'],
    ['targets', 'Target Surfaces','◯'],
    ['arts',    'Articles',      'A'],
    ['actors',  'Threat Actors', '◈'],
  ];

  let total = 0;
  groups.forEach(([k, label, icon]) => {
    const items = grouped[k];
    if (!items.length) return;
    total += items.length;
    const head = document.createElement('div');
    head.className = 'sr-group-head';
    head.innerHTML = _escapeHtml(label) + ' <span class="sr-group-count">' + items.length + '</span>';
    results.appendChild(head);
    items.forEach(({ item }) => {
      const row = document.createElement('div');
      row.className = 'search-result kind-' + item.kind;
      row.innerHTML =
        '<div class="sr-icon">' + _escapeHtml(icon) + '</div>' +
        '<div class="sr-body">' +
          '<div class="sr-title">' + _hl(item.title, q) + '</div>' +
          '<div class="sr-meta">' + _hl(item.meta || '', q) + '</div>' +
        '</div>';
      row.addEventListener('click', () => {
        _addRecent(q);
        closeSearch();
        _navigate(item);
      });
      results.appendChild(row);
      resultEls.push(row);
    });
  });

  if (total === 0) {
    const e = document.createElement('div');
    e.className = 'search-empty';
    e.textContent = 'No matches for "' + q + '"';
    results.appendChild(e);
  } else if (resultEls[0]) {
    resultEls[0].classList.add('sel');
  }
}

// Navigate to the right surface for each kind.
function _navigate(item) {
  if (item.kind === 'art') {
    const el = document.getElementById(item.id);
    if (el) {
      _switchToTab('articles');
      // Defer one frame so the tab-switch repaints before measuring.
      requestAnimationFrame(() => scrollToArticleAccurate(el, 'start'));
      el.classList.add('deeplink-target');
      setTimeout(() => el.classList.remove('deeplink-target'), 1700);
    }
  } else if (item.kind === 'uc') {
    // Use case — try the article-card surface first (fastest), else point
    // the deeplink at the technique landing if we know one.
    const title = item.title || '';
    const allUcs = document.querySelectorAll('#view-articles article.card details.uc');
    let found = null;
    allUcs.forEach(d => {
      if (found) return;
      const t = d.querySelector('summary .uc-title')?.textContent?.trim() || '';
      if (t === title) found = d;
    });
    if (found) {
      _switchToTab('articles');
      found.open = true;
      // Walk up to the owning article.card so content-visibility:auto
      // pre-materialises the right strip before scrolling.
      const ownerCard = found.closest('article.card') || found;
      requestAnimationFrame(() => scrollToArticleAccurate(ownerCard, 'center'));
      found.classList.add('deeplink-target');
      setTimeout(() => found.classList.remove('deeplink-target'), 1700);
    } else {
      // Fall back: open the Library tab and seed the search box with the title
      _switchToTab('detection-library');
      const libSearch = document.querySelector('#view-detection-library input[type="search"], #view-detection-library .lib-search input, #libSearch');
      if (libSearch) { libSearch.value = title; libSearch.dispatchEvent(new Event('input', { bubbles: true })); }
    }
  } else if (item.kind === 'tech') {
    // Send to the per-technique landing page (static, indexable)
    location.href = 'techniques/' + item.tid + '.html';
  } else if (item.kind === 'target') {
    // Per-target landing page — static HTML, indexable
    location.href = 'targets/' + item.slug + '.html';
  } else if (item.kind === 'actor') {
    _switchToTab('actors');
    setTimeout(() => {
      const target = document.querySelector('[data-actor-name="' + item.title + '"]') ||
                     document.querySelector('[data-actor-slug="' + item.slug + '"]');
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.classList.add('deeplink-target');
        setTimeout(() => target.classList.remove('deeplink-target'), 1700);
      }
    }, 250);
  }
}

function _switchToTab(name) {
  // Click the matching nav-tab so existing tab-switch logic runs
  const tabBtn = document.querySelector('[data-tab="' + name + '"], button[data-target="view-' + name + '"]');
  if (tabBtn && !tabBtn.classList.contains('active')) tabBtn.click();
}

input.addEventListener('input', () => _renderResults(input.value));

// =================================================================
// Source filter (Articles tab) — multi-select
// =================================================================
// Click a source chip to toggle its filter on/off. Multiple chips can be
// active at once; a card is shown if it matches ANY active source AND
// every active feature filter ("Has UCs" / "LLM UCs only").
// "All" deselects every other source chip; feature chips are independent.
function applySourceFilter() {
  const activeSourceChips = document.querySelectorAll('#srcFilter .src-chip.active:not(.all):not(.feat-chip):not(.plat-chip):not(.tgt-chip)');
  const activeSources = Array.from(activeSourceChips).map(c => c.dataset.source).filter(Boolean);
  const activeFeats = Array.from(document.querySelectorAll('#srcFilter .feat-chip.active')).map(c => c.dataset.feat);
  const activePlats = Array.from(document.querySelectorAll('#srcFilter .plat-chip.active')).map(c => c.dataset.platform);
  const activeTgts = Array.from(document.querySelectorAll('#srcFilter .tgt-chip.active')).map(c => c.dataset.target);
  const cards = document.querySelectorAll('#view-articles article.card');
  cards.forEach(card => {
    const sources = (card.dataset.sources || '').split('|');
    const platforms = (card.dataset.platforms || '').split(',').filter(Boolean);
    const targets = (card.dataset.targets || '').split(',').filter(Boolean);
    const matchSource = activeSources.length === 0
                        || activeSources.some(s => sources.includes(s));
    const ucCount = parseInt(card.dataset.ucCount || '0', 10);
    const llmCount = parseInt(card.dataset.llmUcCount || '0', 10);
    const matchFeat = activeFeats.every(f => {
      if (f === 'has-uc')  return ucCount > 0;
      if (f === 'has-llm') return llmCount > 0;
      return true;
    });
    // Platform filter is OR within the group (any selected platform matches)
    // and AND with the rest of the filters, mirroring the source-chip pattern.
    const matchPlat = activePlats.length === 0
                      || activePlats.some(p => platforms.includes(p));
    // Target-surface filter — same OR-within / AND-between semantics.
    const matchTgt = activeTgts.length === 0
                     || activeTgts.some(t => targets.includes(t));
    card.classList.toggle('src-hidden', !(matchSource && matchFeat && matchPlat && matchTgt));

    // Drill in: when a Platform filter is active, also hide UCs on this
    // card that don't have the selected platform — otherwise users land
    // on an article that "matches Datadog" but the first UC they see has
    // no Datadog body, which is confusing. When no platform filter is
    // active, every UC stays visible.
    const ucs = card.querySelectorAll('details.uc');
    let firstVisibleUc = null;
    ucs.forEach(uc => {
      const ucPlats = (uc.dataset.platforms || '').split(',').filter(Boolean);
      const ucTgts = (uc.dataset.targets || '').split(',').filter(Boolean);
      const ucMatchPlat = activePlats.length === 0
                          || activePlats.some(p => ucPlats.includes(p));
      const ucMatchTgt = activeTgts.length === 0
                         || activeTgts.some(t => ucTgts.includes(t));
      uc.classList.toggle('uc-platform-hidden', !(ucMatchPlat && ucMatchTgt));
      if (ucMatchPlat && ucMatchTgt && !firstVisibleUc) firstVisibleUc = uc;
    });
    // Auto-open the first matching UC so analysts immediately see the
    // platform body they filtered for. Only re-open when a platform
    // filter is active, otherwise leave the existing open/closed state.
    if ((activePlats.length || activeTgts.length) && firstVisibleUc) {
      ucs.forEach(uc => { if (uc !== firstVisibleUc) uc.open = false; });
      firstVisibleUc.open = true;
      // Switch the active tab to the filtered platform so the right
      // query body is visible without an extra click.
      const targetPlatform = activePlats[0];
      const tabSuffix = {def:'kql', sent:'sentinel', sigma:'sigma', spl:'spl', datadog:'datadog'}[targetPlatform];
      if (tabSuffix) {
        const targetTabBtn = firstVisibleUc.querySelector('.tab-btn[data-target$="-' + tabSuffix + '"]');
        const targetTabPane = firstVisibleUc.querySelector('.tab-content[id$="-' + tabSuffix + '"]');
        if (targetTabBtn && targetTabPane) {
          firstVisibleUc.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
          firstVisibleUc.querySelectorAll('.tab-content').forEach(p => p.classList.remove('active'));
          targetTabBtn.classList.add('active');
          targetTabPane.classList.add('active');
        }
      }
    }
  });
  document.querySelectorAll('#navlist .nav-item').forEach(n => {
    const card = document.getElementById(n.dataset.jump);
    n.style.display = card && card.classList.contains('src-hidden') ? 'none' : '';
  });
  // Keep "All" chip in sync — active iff no source AND no feature filter
  // AND no platform filter chosen.
  const allChip = document.querySelector('#srcFilter .src-chip.all');
  if (allChip) allChip.classList.toggle('active',
    activeSources.length === 0 && activeFeats.length === 0 && activePlats.length === 0 && activeTgts.length === 0);
}
// Pre-populate the count badges on the feature + platform chips on load.
(function() {
  const cards = Array.from(document.querySelectorAll('#view-articles article.card'));
  const hasUc = cards.filter(c => parseInt(c.dataset.ucCount||'0',10) > 0).length;
  const hasLlm = cards.filter(c => parseInt(c.dataset.llmUcCount||'0',10) > 0).length;
  const a = document.getElementById('featCntHasUc');
  const b = document.getElementById('featCntHasLlm');
  if (a) a.textContent = hasUc;
  if (b) b.textContent = hasLlm;
  // Platform counts — how many articles have at least one UC for each platform
  const platCounts = {def:0, sent:0, sigma:0, spl:0, datadog:0};
  for (const c of cards) {
    const p = (c.dataset.platforms || '').split(',').filter(Boolean);
    for (const k of p) if (k in platCounts) platCounts[k]++;
  }
  const idMap = {def:'platCntDef', sent:'platCntSent', sigma:'platCntSigma',
                 spl:'platCntSpl', datadog:'platCntDatadog'};
  for (const k of Object.keys(idMap)) {
    const el = document.getElementById(idMap[k]);
    if (el) el.textContent = platCounts[k];
  }
  // Target-surface chips — built dynamically so we only show targets the
  // current corpus actually has at least one article for. Mirrors the
  // platform-chip layout so analysts get the same toggle semantics.
  const TGT_LABELS = {windows:'Windows', linux:'Linux', macos:'macOS',
                      aws:'AWS', azure:'Azure', gcp:'GCP', kubernetes:'Kubernetes',
                      m365:'M365', okta:'Okta', vcs:'VCS', identity:'Identity',
                      'web-app':'Web App'};
  const tgtCounts = {};
  for (const c of cards) {
    for (const t of (c.dataset.targets || '').split(',').filter(Boolean)) {
      tgtCounts[t] = (tgtCounts[t] || 0) + 1;
    }
  }
  const wrap = document.getElementById('ftTargetChips');
  if (wrap) {
    // Render in TGT_LABELS order, skip ones with zero coverage. The
    // rendered chips share the .src-chip class so the existing click
    // handler at the bottom of this block picks them up automatically.
    const html_ = Object.keys(TGT_LABELS).map(t => {
      const n = tgtCounts[t] || 0;
      if (!n) return '';
      const safeT = t.replace(/[^a-z0-9-]/g,'');
      return '<button class="src-chip tgt-chip" data-target="' + safeT + '" ' +
             'title="Show only articles whose UCs target ' + TGT_LABELS[t] + '">' +
             TGT_LABELS[t] + ' <span class="cnt">' + n + '</span></button>';
    }).join('');
    wrap.innerHTML = html_;
  }
})();
document.querySelectorAll('#srcFilter .src-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    if (chip.classList.contains('all')) {
      // "All" clears every other chip including feature chips
      document.querySelectorAll('#srcFilter .src-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
    } else if (chip.classList.contains('feat-chip')) {
      // Feature chips toggle independently; they don't deactivate sources
      chip.classList.toggle('active');
      document.querySelector('#srcFilter .src-chip.all')?.classList.remove('active');
    } else {
      chip.classList.toggle('active');
      document.querySelector('#srcFilter .src-chip.all')?.classList.remove('active');
    }
    applySourceFilter();
  });
});

// =================================================================
// Width toggle (Articles tab)
// =================================================================
(function(){
  const STORAGE_KEY = 'usecaseintel:width';
  const main = document.querySelector('#view-articles main');
  const toggle = document.getElementById('widthToggle');
  if (!main || !toggle) return;
  function setWidth(mode) {
    main.classList.remove('width-compact','width-wide','width-full');
    main.classList.add('width-' + mode);
    toggle.querySelectorAll('button').forEach(b => {
      b.classList.toggle('on', b.dataset.width === mode);
    });
    try { localStorage.setItem(STORAGE_KEY, mode); } catch(e) {}
  }
  // Restore saved preference (default = 'wide', applied via class on <main>)
  let saved = null;
  try { saved = localStorage.getItem(STORAGE_KEY); } catch(e) {}
  if (saved && ['compact','wide','full'].includes(saved)) setWidth(saved);
  toggle.querySelectorAll('button').forEach(btn => {
    btn.addEventListener('click', () => setWidth(btn.dataset.width));
  });
})();

// =================================================================
// Platform-aware shortcut hint (Cmd on Mac, Ctrl elsewhere)
// =================================================================
(function () {
  const isMac = /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent || '');
  const el = document.getElementById('searchShortcutKey');
  if (el) el.textContent = isMac ? '\u2318' : 'Ctrl';   // ⌘ on Mac
})();

// =================================================================
// Detection Library — preprocesses every UC into a search-friendly
// shape, derives SOC Value Score, extracts queries from the article
// DOM, and renders a card grid + structured detail drawer.
// =================================================================
const LIB_STATE = {
  prepared: null,
  filters: {
    search: '',
    phase: '',
    tactic: '',
    severity: '',
    tier: '',
    src: '',
    actor: '',
    country: '',
    app: '',
    platforms: new Set(),
    // Target-surface filter (windows/linux/aws/azure/gcp/kubernetes/m365/
    // okta/vcs/identity/web-app/macos). Multi-select; UC must have AT
    // LEAST one of the selected tags to pass — analyst asking for "Linux
    // OR AWS" should see both, not just intersection.
    targets: new Set(),
    // Use-case kind: 'normal' (hand-built catalog + ESCU), 'llm' (per-article
    // LLM-generated, title starts [LLM]), 'wkc' (Weekly Kill Chain — biweekly
    // cross-article synthesis, title starts [WEEKLY]). Multi-select, OR-combined.
    kinds: new Set(),
  },
};

// Display metadata for target-surface filter pills. Mirrors TARGET_DISPLAY
// in generate.py — keep in sync if you add a new target there.
const TARGET_PILL_META = [
  ['windows',    'Windows'],
  ['linux',      'Linux'],
  ['macos',      'macOS'],
  ['aws',        'AWS'],
  ['azure',      'Azure'],
  ['gcp',        'GCP'],
  ['kubernetes', 'Kubernetes'],
  ['m365',       'M365'],
  ['okta',       'Okta'],
  ['vcs',        'Source control'],
  ['identity',   'Identity'],
  ['web-app',    'Web App'],
];

const SEV_ORDER = {crit: 4, critical: 4, high: 3, med: 2, medium: 2, low: 1, info: 0};
const SEV_NORM = {crit:'crit', critical:'crit', high:'high', med:'med', medium:'med', low:'low', info:'low'};

// Friendly tactic display lifted from the matrix view. Populated lazily
// on first library render — the MATRIX const lives later in this script
// block and accessing it at top-level here would hit the TDZ and halt
// the rest of the script (which silently breaks every tab click).
const TACTIC_NAME = {};
function _libPopulateTactics() {
  if (Object.keys(TACTIC_NAME).length) return;
  try {
    if (MATRIX && MATRIX.tactics) {
      for (const t of MATRIX.tactics) TACTIC_NAME[t.short] = t.name;
    }
  } catch (_) { /* MATRIX not initialised yet */ }
}

// Heuristic application/binary tags surfaced as filters and pills so an
// analyst can ask "show me everything that mentions powershell".
const LIB_APP_PATTERNS = [
  ['powershell', /\\b(powershell\\.exe|powershell|pwsh)\\b/i],
  ['cmd',        /\\bcmd\\.exe\\b/i],
  ['regsvr32',   /\\bregsvr32\\.exe\\b/i],
  ['rundll32',   /\\brundll32\\.exe\\b/i],
  ['mshta',      /\\bmshta\\.exe\\b/i],
  ['certutil',   /\\bcertutil\\.exe\\b/i],
  ['bitsadmin',  /\\bbitsadmin\\.exe\\b/i],
  ['wmic',       /\\bwmic\\.exe\\b/i],
  ['msbuild',    /\\bmsbuild\\.exe\\b/i],
  ['installutil',/\\binstallutil\\.exe\\b/i],
  ['lsass',      /\\blsass\\.exe\\b/i],
  ['wscript',    /\\b(wscript|cscript)\\.exe\\b/i],
  ['psexec',     /\\bpsexec\\.?(exe)?\\b/i],
  ['office',     /\\b(winword|excel|outlook|powerpnt|onenote)\\.exe\\b/i],
  ['browser',    /\\b(chrome|firefox|msedge|edge|brave|safari)\\.exe\\b/i],
  ['ssh',        /\\bssh(?:\\.exe)?\\b/i],
  ['curl',       /\\bcurl(?:\\.exe)?\\b/i],
  ['scheduledtask', /\\bschtasks\\.exe\\b/i],
];

const LIB_ACTORS = [
  {n:'APT28', c:'Russia'}, {n:'APT29', c:'Russia'}, {n:'Sandworm', c:'Russia'},
  {n:'Sednit', c:'Russia'}, {n:'Fancy Bear', c:'Russia'}, {n:'Forest Blizzard', c:'Russia'},
  {n:'Gamaredon', c:'Russia'}, {n:'Turla', c:'Russia'}, {n:'Cozy Bear', c:'Russia'},
  {n:'Lazarus', c:'North Korea'}, {n:'Kimsuky', c:'North Korea'},
  {n:'APT37', c:'North Korea'}, {n:'APT38', c:'North Korea'},
  {n:'APT41', c:'China'}, {n:'APT10', c:'China'}, {n:'APT40', c:'China'},
  {n:'Mustang Panda', c:'China'}, {n:'Volt Typhoon', c:'China'},
  {n:'Salt Typhoon', c:'China'}, {n:'Silver Fox', c:'China'},
  {n:'PlushDaemon', c:'China'}, {n:'PlugX', c:'China'},
  {n:'APT34', c:'Iran'}, {n:'OilRig', c:'Iran'}, {n:'MuddyWater', c:'Iran'},
  {n:'Charming Kitten', c:'Iran'},
  {n:'FIN7', c:'E-crime'}, {n:'FIN8', c:'E-crime'}, {n:'TA505', c:'E-crime'},
  {n:'Cordial Spider', c:'E-crime'}, {n:'Snarky Spider', c:'E-crime'},
  {n:'Scattered Spider', c:'E-crime'}, {n:'LockBit', c:'E-crime'},
  {n:'BlackCat', c:'E-crime'}, {n:'ALPHV', c:'E-crime'},
];

function _libExtractApps(text) {
  const found = new Set();
  for (const [tag, re] of LIB_APP_PATTERNS) if (re.test(text)) found.add(tag);
  return [...found];
}
function _libExtractActors(text) {
  const found = [];
  for (const a of LIB_ACTORS) {
    const re = new RegExp('\\\\b' + a.n.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + '\\\\b', 'i');
    if (re.test(text)) found.push(a);
  }
  return found;
}
function _libSourceFromArtId(art) {
  const t = (art.title || '').toLowerCase();
  if (/\\bcisa\\b/.test(t)) return 'CISA KEV';
  if (/(hackers? news|the hacker news)/.test(t)) return 'Hacker News';
  if (/bleeping/.test(t)) return 'BleepingComputer';
  if (/\\beset\\b|welive/.test(t)) return 'ESET';
  if (/talos/.test(t)) return 'Talos';
  if (/unit\\s*42/.test(t)) return 'Unit 42';
  if (/sentinellabs|sentinelone/.test(t)) return 'SentinelLabs';
  if (/securelist|kaspersky/.test(t)) return 'Securelist';
  if (/microsoft/.test(t)) return 'Microsoft';
  if (/lab\\s*52/.test(t)) return 'Lab52';
  if (/cybersecuritynews/.test(t)) return 'Cyber Security News';
  if (/\\bsnyk\\b/.test(t)) return 'Snyk';
  if (/aikido/.test(t)) return 'Aikido';
  if (/stepsecurity|step-security/.test(t)) return 'StepSecurity';
  if (/\\bghsa\\b|github security advisor/.test(t)) return 'GHSA';
  return 'Other';
}

function _libPrepare() {
  if (LIB_STATE.prepared) return LIB_STATE.prepared;
  _libPopulateTactics();
  // Defensive — MATRIX is declared elsewhere; guard against it being missing.
  let M;
  try { M = MATRIX; } catch (_) { return []; }
  if (!M || !Array.isArray(M.ucs)) return [];
  const arts = M.arts || [];

  // Pull each UC's per-platform query bodies straight off the rendered
  // tab-content divs. The id suffix tells us the platform unambiguously
  // (e.g. id="art-01-uc0-datadog") which is far more reliable than
  // content-sniffing the query text — KQL pipes can look like SPL,
  // Datadog queries don't always start with "source:", etc.
  // Platform flags themselves are read from each MATRIX record's
  // canonical `pl` field below; this map is used only by the drawer
  // to display the actual query body when a UC is opened.
  const ucDom = new Map();
  const KIND_BY_SUFFIX = {kql:'def', sentinel:'sent', sigma:'sigma', datadog:'datadog', spl:'spl'};
  document.querySelectorAll('#view-articles article.card details.uc').forEach(d => {
    const title = (d.querySelector('summary .uc-title')?.textContent || d.querySelector('summary')?.textContent || '').trim();
    if (!title) return;
    const queries = {};
    d.querySelectorAll('.tab-content').forEach(tc => {
      const m = (tc.id || '').match(/-(kql|sentinel|sigma|datadog|spl)$/);
      if (!m) return;
      const codeEl = tc.querySelector('pre code');
      const txt = (codeEl ? codeEl.textContent : '').trim();
      if (!txt || txt.length > 8000) return;
      const kind = KIND_BY_SUFFIX[m[1]];
      if (kind && !queries[kind]) queries[kind] = txt;
    });
    ucDom.set(title, {queries});
  });

  const prepared = M.ucs.map(uc => {
    const ucArts = (uc.arts || []).map(i => arts[i]).filter(Boolean);
    let maxSev = 0; let sevTag = 'low';
    for (const a of ucArts) {
      const r = SEV_ORDER[(a.sev || '').toLowerCase()] || 0;
      if (r > maxSev) { maxSev = r; sevTag = SEV_NORM[(a.sev || '').toLowerCase()] || 'low'; }
    }
    // Read platform flags from the canonical `pl` field on the matrix
    // record (built from each UseCase's actual *_kql / *_yaml / *_query
    // attributes in build_matrix_data). Position 0=Defender (d/-),
    // 1=Sentinel (s/-), 2=Sigma (g/-), 3=Splunk (p/-), 4=Datadog (D/-).
    const pl = uc.pl || '';
    const plats = {
      def:     pl.charAt(0) === 'd',
      sent:    pl.charAt(1) === 's',
      sigma:   pl.charAt(2) === 'g',
      spl:     pl.charAt(3) === 'p',
      datadog: pl.charAt(4) === 'D',
    };
    const queries = ucDom.get(uc.t)?.queries || {};
    const apps = _libExtractApps(uc.t + ' ' + (uc.n || ''));
    const actorTitles = ucArts.map(a => a.title).join(' || ');
    const actors = _libExtractActors(actorTitles);
    const countries = [...new Set(actors.map(a => a.c))];
    const sources = [...new Set(ucArts.map(a => _libSourceFromArtId(a)))];

    const tacticSet = new Set();
    for (const tid of (uc.techs || [])) {
      const t = M.techniques?.[tid];
      if (t && t.tactics) for (const tac of t.tactics) tacticSet.add(tac);
    }

    const probability   = Math.min(100, Math.round(Math.log2(1 + ucArts.length) * 22));
    const impact        = ({0:20, 1:35, 2:55, 3:80, 4:100})[maxSev] ?? 30;
    const platformCount = ['def','sent','sigma','spl','datadog'].filter(k => plats[k]).length;
    const detectability = Math.round((platformCount / 5) * 100);
    const queryLines = Object.values(queries).reduce((s, q) => s + q.split('\\n').length, 0) || 18;
    const effort = Math.max(20, Math.min(100, 110 - Math.round(queryLines * 1.6)));
    const score  = Math.round(0.30 * probability + 0.30 * impact + 0.25 * detectability + 0.15 * effort);

    // Target-surface tags from the matrix record. Built once during
    // pipeline run by `_infer_uc_targets()` against the actual query
    // bodies — see the `tg` field in build_matrix_data().
    const targets = Array.isArray(uc.tg) ? uc.tg.slice() : [];
    // Use-case kind. WKC = Weekly Kill Chain (biweekly cross-article
    // synthesis), LLM = per-article LLM-generated, Normal = everything else
    // (hand-built catalog + ESCU). Title prefix is the canonical marker,
    // with id prefix + src as fallbacks.
    const _t = uc.t || '';
    const _n = uc.n || '';
    let kind = 'normal';
    if (_t.startsWith('[WEEKLY]') || _n.startsWith('UC_WEEKLY_')) kind = 'wkc';
    else if (_t.startsWith('[LLM]') || uc.src === 'bespoke' || uc.src === 'llm') kind = 'llm';
    return {
      uc, ucArts, sevTag, sevRank: maxSev, plats, queries, apps, actors, countries, sources,
      tactics: [...tacticSet],
      targets,
      kind,
      score, breakdown: {probability, impact, detectability, effort},
      _idx: uc.i,
      _searchBlob: [
        uc.n, uc.t, (uc.techs || []).join(' '),
        actors.map(a => a.n).join(' '),
        countries.join(' '),
        apps.join(' '),
        ucArts.map(a => a.title).join(' '),
        targets.join(' '),
      ].join(' ').toLowerCase(),
    };
  });

  prepared.sort((a, b) => b.score - a.score);
  LIB_STATE.prepared = prepared;
  return prepared;
}

function _libBuildFilters(prepared) {
  const phases = new Set(); const tiers = new Set(); const srcs = new Set();
  const tactics = new Set(); const apps = new Set();
  const actors = new Set(); const countries = new Set();
  for (const p of prepared) {
    if (p.uc.ph) phases.add(p.uc.ph);
    if (p.uc.tier) tiers.add(p.uc.tier);
    if (p.uc.src) srcs.add(p.uc.src);
    for (const t of p.tactics) tactics.add(t);
    for (const a of p.apps) apps.add(a);
    for (const a of p.actors) actors.add(a.n);
    for (const c of p.countries) countries.add(c);
  }
  function selectChip(label, key, items, formatter) {
    const opts = ['<option value="">All</option>'].concat(
      [...items].sort().map(v => `<option value="${escapeHtml(v)}">${escapeHtml((formatter||((x)=>x))(v))}</option>`)
    ).join('');
    return `<label class="lib-filter-group"><span class="lf-label">${escapeHtml(label)}</span>
      <select data-lib-filter="${escapeHtml(key)}">${opts}</select></label>`;
  }
  const sevSel = selectChip('Severity', 'severity', ['crit','high','med','low'], v => ({crit:'Critical', high:'High', med:'Medium', low:'Low'}[v]||v));
  const phaseSel = selectChip('Phase', 'phase', phases);
  const tacticSel = selectChip('Tactic', 'tactic', tactics, v => TACTIC_NAME[v] || v);
  const tierSel = selectChip('Tier', 'tier', tiers, v => v[0].toUpperCase() + v.slice(1));
  const srcSel = selectChip('Source', 'src', srcs, v => v === 'internal' ? 'Internal' : 'LLM');
  const appSel = selectChip('App', 'app', apps);
  const actorSel = selectChip('Actor', 'actor', actors);
  const countrySel = selectChip('Country', 'country', countries);
  const platformPills = `<div class="lib-pill-group" data-lib-platforms>
    <button class="lib-pill platform-d" data-pl="def">D · Defender</button>
    <button class="lib-pill platform-s" data-pl="sent">S · Sentinel</button>
    <button class="lib-pill platform-z" data-pl="sigma">Σ · Sigma</button>
    <button class="lib-pill platform-p" data-pl="spl">P · Splunk</button>
    <button class="lib-pill platform-dd" data-pl="datadog">DD · Datadog</button>
  </div>`;
  // Kind pills — Normal / LLM / WKC. Counts come from the prepared set so
  // the analyst sees how many UCs are in each bucket. Hover-title explains
  // what each bucket actually contains.
  const kCounts = {normal:0, llm:0, wkc:0};
  for (const p of prepared) kCounts[p.kind] = (kCounts[p.kind] || 0) + 1;
  const KIND_META = [
    ['normal', 'Normal', 'Hand-built catalogue use cases + synced Splunk ESCU detections — reviewed and stable.'],
    ['llm',    'LLM',    'Per-article LLM-generated use cases (titles prefixed [LLM]) — auto-synthesised from each new article in the daily pipeline.'],
    ['wkc',    'WKC',    'Weekly Kill-Chain use cases (titles prefixed [WEEKLY]) — biweekly cross-article LLM synthesis covering recurring themes and trending CVEs.'],
  ];
  const kindPills = `<div class="lib-pill-group lib-kind-pills" data-lib-kinds>` +
    KIND_META.map(([k, label, tip]) =>
      `<button class="lib-pill lib-kind lib-kind-${k}" data-kind="${k}" title="${escapeHtml(tip)}">${escapeHtml(label)} <span class="cnt">${kCounts[k]||0}</span></button>`
    ).join('') + `</div>`;
  // Target-surface pills row. Counts populated from the actual prepared
  // dataset so the analyst sees how many UCs each tag will return.
  const tCounts = {};
  for (const p of prepared) for (const t of (p.targets || [])) tCounts[t] = (tCounts[t] || 0) + 1;
  const targetPills = `<div class="lib-pill-group lib-target-pills" data-lib-targets>` +
    TARGET_PILL_META.map(([tag, label]) => {
      const c = tCounts[tag] || 0;
      // Hide tags with zero coverage to keep the row tidy.
      if (!c) return '';
      return `<button class="lib-pill lib-target" data-target="${escapeHtml(tag)}">${escapeHtml(label)} <span class="cnt">${c}</span></button>`;
    }).filter(Boolean).join('') + `</div>`;
  const clear = `<button type="button" class="lib-clear-btn" id="libClearFilters">Clear all</button>`;
  return [sevSel, phaseSel, tacticSel, tierSel, srcSel, appSel, actorSel, countrySel, kindPills, platformPills, targetPills, clear].join(' ');
}

function _libCardHtml(p) {
  const tacticLabel = p.tactics[0] ? (TACTIC_NAME[p.tactics[0]] || p.tactics[0]) : '';
  const tacticTag = tacticLabel ? `<span class="lib-tag tactic">${escapeHtml(tacticLabel)}</span>` : '';
  const sevTag = `<span class="lib-tag sev-${p.sevTag}">${p.sevTag.toUpperCase()}</span>`;
  const tierTag = p.uc.tier ? `<span class="lib-tag tier">${escapeHtml(p.uc.tier)}</span>` : '';
  const platTags = ['def','sent','sigma','spl','datadog'].filter(k => p.plats[k]).map(k => {
    const cls = {def:'platform-d', sent:'platform-s', sigma:'platform-z', spl:'platform-p', datadog:'platform-dd'}[k];
    const label = {def:'D', sent:'S', sigma:'Σ', spl:'P', datadog:'DD'}[k];
    return `<span class="lib-tag ${cls}" title="${k}">${label}</span>`;
  }).join('');
  const techPills = (p.uc.techs || []).slice(0, 4).map(t => `<span class="lib-tag">${escapeHtml(t)}</span>`).join('');
  const moreTechs = (p.uc.techs || []).length > 4 ? `<span class="lib-tag" title="${escapeHtml((p.uc.techs||[]).join(', '))}">+${(p.uc.techs||[]).length - 4}</span>` : '';
  // Compact per-card target-surface tags so the analyst can tell at a
  // glance whether this is Windows-only, AWS, M365, etc.
  const _TGT_LABEL = {windows:'Windows', linux:'Linux', macos:'macOS', aws:'AWS', azure:'Azure', gcp:'GCP', kubernetes:'K8s', m365:'M365', okta:'Okta', vcs:'VCS', identity:'Identity', 'web-app':'WebApp'};
  const tgtTags = (p.targets || []).slice(0, 3).map(t =>
    `<span class="lib-tag lib-tg lib-tg-${escapeHtml(t)}" title="Target surface: ${escapeHtml(_TGT_LABEL[t] || t)}">${escapeHtml(_TGT_LABEL[t] || t)}</span>`
  ).join('');
  const moreTgt = (p.targets || []).length > 3 ? `<span class="lib-tag lib-tg" title="${escapeHtml((p.targets||[]).join(', '))}">+${(p.targets||[]).length - 3}</span>` : '';
  return `<article class="lib-card" role="listitem" data-uc-idx="${p._idx}">
    <div class="lib-card-head">
      <div style="flex:1;">
        <div class="lib-card-name">${escapeHtml(p.uc.t || p.uc.n)}</div>
        <div class="lib-card-id">${escapeHtml(p.uc.n)}</div>
      </div>
    </div>
    <div class="lib-card-meta">
      ${sevTag}${tacticTag}${tierTag}${techPills}${moreTechs}${tgtTags}${moreTgt}${platTags}
    </div>
    <div class="lib-card-footer">
      <div class="lib-svs" title="SOC Value Score">
        <span class="lib-svs-num">${p.score}</span>
        <span>SVS</span>
      </div>
      <div class="lib-svs-track"><div class="lib-svs-fill" style="width:${p.score}%"></div></div>
      <div class="lib-card-articles">${p.ucArts.length} ${p.ucArts.length === 1 ? 'sighting' : 'sightings'}</div>
    </div>
  </article>`;
}

function _libApplyFilters(prepared) {
  const f = LIB_STATE.filters;
  return prepared.filter(p => {
    if (f.search) {
      if (!p._searchBlob.includes(f.search)) return false;
    }
    if (f.phase   && p.uc.ph !== f.phase) return false;
    if (f.tactic  && !p.tactics.includes(f.tactic)) return false;
    if (f.severity && p.sevTag !== f.severity) return false;
    if (f.tier    && p.uc.tier !== f.tier) return false;
    if (f.src     && p.uc.src !== f.src) return false;
    if (f.actor   && !p.actors.some(a => a.n === f.actor)) return false;
    if (f.country && !p.countries.includes(f.country)) return false;
    if (f.app     && !p.apps.includes(f.app)) return false;
    if (f.kinds && f.kinds.size) {
      if (!f.kinds.has(p.kind)) return false;
    }
    if (f.platforms.size) {
      for (const k of f.platforms) if (!p.plats[k]) return false;
    }
    // Targets are OR-combined within the filter (Linux pill OR AWS pill
    // shows everything tagged with either) but AND-combined with the
    // other filters above.
    if (f.targets && f.targets.size) {
      const tgs = p.targets || [];
      let any = false;
      for (const t of f.targets) if (tgs.includes(t)) { any = true; break; }
      if (!any) return false;
    }
    return true;
  });
}

function _libRenderCards() {
  const prepared = _libPrepare();
  const filtered = _libApplyFilters(prepared);
  const grid = document.getElementById('libGrid');
  const count = document.getElementById('libResultCount');
  if (count) count.textContent = `${filtered.length.toLocaleString()} of ${prepared.length.toLocaleString()} use cases`;

  // Top-bar stats — mirrors the .stat shape used by Articles / Matrix /
  // Intel / Actors so the centred sliding-stats CSS picks it up.
  const topLib = document.getElementById('topStatsLibrary');
  if (topLib) {
    let critical = 0;
    const plats  = {def:0, sent:0, sigma:0, spl:0, datadog:0};
    for (const p of prepared) {
      if (p.sevTag === 'crit') critical++;
      if (p.plats) {
        if (p.plats.def)     plats.def++;
        if (p.plats.sent)    plats.sent++;
        if (p.plats.sigma)   plats.sigma++;
        if (p.plats.spl)     plats.spl++;
        if (p.plats.datadog) plats.datadog++;
      }
    }
    const platformsCovered = Object.values(plats).filter(n => n > 0).length;
    topLib.innerHTML =
      `<div class="stat"><div class="v">${prepared.length.toLocaleString()}</div><div class="l">Use Cases</div></div>` +
      `<div class="stat"><div class="v">${platformsCovered.toLocaleString()}</div><div class="l">Platforms</div></div>` +
      `<div class="stat"><div class="v">${critical.toLocaleString()}</div><div class="l">Critical</div></div>`;
  }

  if (!grid) return;
  if (!filtered.length) {
    grid.innerHTML = `<div class="lib-empty"><b>No use cases match these filters.</b><br>Try clearing a filter or changing your search.</div>`;
    return;
  }
  const cap = 240;
  grid.innerHTML = filtered.slice(0, cap).map(_libCardHtml).join('');
  if (filtered.length > cap) {
    const more = document.createElement('div');
    more.className = 'lib-empty';
    more.innerHTML = `<b>${(filtered.length - cap).toLocaleString()} more results</b><br>Refine your filters to see them.`;
    grid.appendChild(more);
  }
}

function renderLibrary() {
  const filters = document.getElementById('libFilters');
  if (filters && !filters.dataset.ready) {
    filters.innerHTML = _libBuildFilters(_libPrepare());
    filters.dataset.ready = '1';
    filters.addEventListener('change', e => {
      const sel = e.target.closest('select[data-lib-filter]');
      if (!sel) return;
      LIB_STATE.filters[sel.dataset.libFilter] = sel.value;
      _libRenderCards();
    });
    filters.addEventListener('click', e => {
      const pill = e.target.closest('.lib-pill[data-pl]');
      if (pill) {
        const k = pill.dataset.pl;
        if (LIB_STATE.filters.platforms.has(k)) LIB_STATE.filters.platforms.delete(k);
        else LIB_STATE.filters.platforms.add(k);
        pill.classList.toggle('on');
        _libRenderCards();
        return;
      }
      // Target-surface pill toggle (Windows / Linux / AWS / ...)
      const tpill = e.target.closest('.lib-pill[data-target]');
      if (tpill) {
        const k = tpill.dataset.target;
        if (LIB_STATE.filters.targets.has(k)) LIB_STATE.filters.targets.delete(k);
        else LIB_STATE.filters.targets.add(k);
        tpill.classList.toggle('on');
        _libRenderCards();
        return;
      }
      // Kind pill toggle (Normal / LLM / WKC)
      const kpill = e.target.closest('.lib-pill[data-kind]');
      if (kpill) {
        const k = kpill.dataset.kind;
        if (LIB_STATE.filters.kinds.has(k)) LIB_STATE.filters.kinds.delete(k);
        else LIB_STATE.filters.kinds.add(k);
        kpill.classList.toggle('on');
        _libRenderCards();
        return;
      }
      if (e.target.id === 'libClearFilters') {
        LIB_STATE.filters = {search:'', phase:'', tactic:'', severity:'', tier:'', src:'', actor:'', country:'', app:'', platforms:new Set(), targets:new Set(), kinds:new Set()};
        filters.querySelectorAll('select[data-lib-filter]').forEach(s => s.value = '');
        filters.querySelectorAll('.lib-pill.on').forEach(p => p.classList.remove('on'));
        const search = document.getElementById('libSearch');
        if (search) search.value = '';
        _libRenderCards();
      }
    });
  }
  const search = document.getElementById('libSearch');
  if (search && !search.dataset.ready) {
    search.dataset.ready = '1';
    let t = null;
    search.addEventListener('input', () => {
      clearTimeout(t);
      t = setTimeout(() => {
        LIB_STATE.filters.search = search.value.trim().toLowerCase();
        _libRenderCards();
      }, 80);
    });
  }
  _libRenderCards();
}

document.addEventListener('click', e => {
  const card = e.target.closest('.lib-card[data-uc-idx]');
  if (!card) return;
  const idx = parseInt(card.dataset.ucIdx, 10);
  const prepared = _libPrepare();
  const p = prepared.find(x => x._idx === idx);
  if (p) openLibraryDrawer(p);
});

function openLibraryDrawer(p) {
  const drawer = document.getElementById('libDrawer');
  const content = document.getElementById('libDrawerContent');
  if (!drawer || !content) return;
  content.innerHTML = _libDetailHtml(p);
  drawer.removeAttribute('hidden');
  requestAnimationFrame(() => drawer.classList.add('open'));
  drawer.scrollTop = 0;
  if (content.parentElement) content.parentElement.scrollTop = 0;
  content.querySelectorAll('.lib-query-tab').forEach(b => {
    b.addEventListener('click', () => {
      const k = b.dataset.platform;
      content.querySelectorAll('.lib-query-tab').forEach(x => x.classList.toggle('on', x === b));
      content.querySelectorAll('[data-query-pane]').forEach(pane => {
        pane.style.display = pane.dataset.queryPane === k ? '' : 'none';
      });
    });
  });
  content.querySelectorAll('.lib-copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const pane = btn.closest('[data-query-pane]');
      if (!pane) return;
      // Prefer the .active body when the pane has a Summarised/
      // Non-summarised toggle; otherwise just take the first <pre>.
      const pre = pane.querySelector('.spl-mode-body.active') || pane.querySelector('pre');
      if (!pre) return;
      try {
        await navigator.clipboard.writeText(pre.textContent || '');
        btn.classList.add('copied'); btn.textContent = 'Copied ✓';
        setTimeout(() => { btn.classList.remove('copied'); btn.textContent = 'Copy'; }, 1400);
      } catch (_) {
        btn.textContent = 'Copy failed';
      }
    });
  });
}
function closeLibraryDrawer() {
  const drawer = document.getElementById('libDrawer');
  if (!drawer) return;
  drawer.classList.remove('open');
  setTimeout(() => drawer.setAttribute('hidden', ''), 300);
}
document.getElementById('libDrawerClose')?.addEventListener('click', closeLibraryDrawer);
document.getElementById('libDrawer')?.addEventListener('click', e => {
  if (e.target.id === 'libDrawer') closeLibraryDrawer();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !document.getElementById('libDrawer')?.hasAttribute('hidden')) {
    closeLibraryDrawer();
  }
});

function _libFpTuning(p) {
  const techs = p.uc.techs || [];
  const phase = p.uc.ph || '';
  const fp = []; const tune = [];
  if (techs.some(t => /^T1059/.test(t))) {
    fp.push('Legitimate admin / IT-automation scripts (deployment tooling, RMM, configuration management) often invoke the same shells with similar flags.');
    tune.push('Allow-list signed admin scripts by hash or by parent process (e.g. SCCM, Intune) before alerting; consider firing only outside of change-windows.');
  }
  if (techs.some(t => /^T1003/.test(t)) || /\\blsass\\b/i.test(p.uc.t)) {
    fp.push('Memory-protection products (CrowdStrike, Defender, third-party EDR) routinely open LSASS for inspection.');
    tune.push('Exclude known security-product binaries by signed-publisher; alert only when the requesting process is unsigned or has no parent.');
  }
  if (techs.some(t => /^T1027/.test(t))) {
    fp.push('Packers and obfuscators are also used by legitimate installers (Inno Setup, NSIS) and game protectors.');
    tune.push('Combine entropy + signing-status — high-entropy + unsigned + outside %ProgramFiles% is the actionable combination.');
  }
  if (techs.some(t => /^T1218/.test(t))) {
    fp.push('LOLBins (mshta, regsvr32, rundll32) appear in legitimate provisioning and Office macros.');
    tune.push('Alert on the parent-process / commandline pair (e.g. winword.exe → mshta.exe http\\\\:* is rarely benign).');
  }
  if (/exfil/i.test(p.uc.t) || phase === 'exfil') {
    fp.push('Cloud-backup tooling (OneDrive, Dropbox, GDrive sync, Backblaze) generates similar bulk outbound flows.');
    tune.push('Allow-list known cloud-backup destinations by SNI / fronted FQDN; alert on uncommon destinations or unusual hours.');
  }
  if (/(beacon|c2|command-and-control)/i.test(p.uc.t + ' ' + phase)) {
    fp.push('Long-poll APIs, telemetry agents, and SaaS heartbeats can mimic beaconing cadence.');
    tune.push('Score on jitter + small payload-size + low domain-popularity rather than periodicity alone.');
  }
  if (techs.some(t => /^T1566/.test(t))) {
    fp.push('Marketing emails and helpdesk auto-replies generate similar URL-click telemetry.');
    tune.push('Cross-reference the click-time URL against your vendor/partner safe-list before escalating.');
  }
  if (!fp.length) {
    fp.push('Authorised administrators or build/CI tooling can produce the same telemetry signatures.');
    tune.push("Allow-list the operations team's service accounts and known maintenance windows; tighten the time-of-day filter to off-hours for higher-fidelity firing.");
  }
  return {fp, tune};
}

function _libDetailHtml(p) {
  const tacticChips = p.tactics.map(t => `<span class="lib-tag tactic">${escapeHtml(TACTIC_NAME[t] || t)}</span>`).join('');
  const sevTag = `<span class="lib-tag sev-${p.sevTag}">${p.sevTag.toUpperCase()}</span>`;
  const tierTag = p.uc.tier ? `<span class="lib-tag tier">${escapeHtml(p.uc.tier)}</span>` : '';
  const phaseTag = p.uc.ph ? `<span class="lib-tag">${escapeHtml(p.uc.ph)}</span>` : '';
  const platTags = ['def','sent','sigma','spl','datadog'].filter(k => p.plats[k]).map(k => {
    const cls = {def:'platform-d', sent:'platform-s', sigma:'platform-z', spl:'platform-p', datadog:'platform-dd'}[k];
    const lbl = {def:'Defender KQL', sent:'Sentinel KQL', sigma:'Sigma', spl:'Splunk SPL', datadog:'Datadog'}[k];
    return `<span class="lib-tag ${cls}">${escapeHtml(lbl)}</span>`;
  }).join('');

  const svsGrid = ['probability','impact','detectability','effort'].map(k => {
    const v = p.breakdown[k];
    const label = {probability:'Probability', impact:'Impact', detectability:'Detectability', effort:'Low Effort'}[k];
    return `<div class="lib-svs-component">
      <span class="lib-svs-component-label">${label}</span>
      <div class="lib-svs-component-bar"><div class="lib-svs-component-fill" style="width:${v}%"></div></div>
      <span class="lib-svs-component-val">${v}/100</span>
    </div>`;
  }).join('');

  const mitre = (p.uc.techs || []).map(tid => {
    const t = MATRIX.techniques?.[tid] || {};
    const tac = (t.tactics && t.tactics[0]) ? (TACTIC_NAME[t.tactics[0]] || t.tactics[0]) : '';
    const url = `https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`;
    return `<a class="lib-mitre-pill" href="${url}" target="_blank" rel="noopener">
      <span class="mp-tid">${escapeHtml(tid)}</span>
      <span class="mp-name">${escapeHtml(t.name || tid)}</span>
      ${tac ? `<span class="mp-tactic">${escapeHtml(tac)}</span>` : ''}
    </a>`;
  }).join('');

  const descLine = p.uc.t || p.uc.n;
  const descIntro = (() => {
    const tCount = (p.uc.techs || []).length;
    const phaseLabel = p.uc.ph ? `the <b>${escapeHtml(p.uc.ph)}</b> phase` : 'multiple kill-chain phases';
    return `Detects activity matching ${escapeHtml(descLine)}. Maps to ${tCount} MITRE technique${tCount === 1 ? '' : 's'} across ${phaseLabel}; tuned for ${p.uc.tier === 'alerting' ? 'alert-grade fidelity' : 'analyst hunting'}.`;
  })();

  const platOrder = ['def','sent','sigma','spl','datadog'];
  const havePlats = platOrder.filter(k => p.queries[k]);
  const queryTabs = havePlats.length ? havePlats.map((k, i) => {
    const lbl = {def:'Defender KQL', sent:'Sentinel KQL', sigma:'Sigma', spl:'Splunk SPL', datadog:'Datadog'}[k];
    return `<button class="lib-query-tab ${i === 0 ? 'on' : ''}" data-platform="${k}">${lbl}</button>`;
  }).join('') : '';
  const queryPanes = havePlats.length ? havePlats.map((k, i) => {
    const meta = ({def:'Microsoft Defender Advanced Hunting · KQL', sent:'Microsoft Sentinel · KQL', sigma:'Sigma rule (compiles to KQL/SPL/Lucene at build)', spl:'Splunk SPL', datadog:'Datadog Cloud SIEM · logs query'}[k]);
    const body = p.queries[k] || '';
    // Splunk gets the same Summarised / Non-summarised toggle the article
    // cards have when the query has a tstats acceleration form. Computed
    // client-side via _splUnsummarised so the drawer doesn't need pre-
    // baked alternatives.
    const splAlt = (k === 'spl') ? _splUnsummarised(body) : body;
    const splDual = (k === 'spl' && splAlt !== body);
    const drawerUid = 'lib-' + (p.uc.n || p.uc.t || '').replace(/[^A-Za-z0-9_-]/g, '_');
    let inner;
    if (splDual) {
      inner = `<div class="spl-toggle-group">
        <div class="spl-mode-toggle">
          <button class="spl-mode-btn active" data-spl-mode="acc" data-target="${drawerUid}-spl-acc">Summarised</button>
          <button class="spl-mode-btn" data-spl-mode="raw" data-target="${drawerUid}-spl-raw">Non-summarised</button>
          <span class="spl-mode-hint">Toggle if your env has no CIM data-model acceleration.</span>
        </div>
        <pre class="spl-mode-body active lib-query-pre" id="${drawerUid}-spl-acc">${escapeHtml(body)}</pre>
        <pre class="spl-mode-body lib-query-pre" id="${drawerUid}-spl-raw">${escapeHtml(splAlt)}</pre>
      </div>`;
    } else {
      inner = `<pre class="lib-query-pre">${escapeHtml(body)}</pre>`;
    }
    return `<div data-query-pane="${k}" style="${i === 0 ? '' : 'display:none;'}">
      <div class="lib-query-toolbar">
        <span class="lib-query-meta">${meta}</span>
        <button type="button" class="lib-copy-btn">Copy</button>
      </div>
      ${inner}
    </div>`;
  }).join('') : `<div class="lib-section-body" style="color:var(--muted);">Queries for this UC live on the original article cards in the <b>Articles</b> tab — open one of the sightings below to see them inline. (We're working on extracting them into the library directly.)</div>`;

  const tablesFound = new Set();
  const KQL_TABLES = /(\\b(?:Device(?:ProcessEvents|FileEvents|NetworkEvents|RegistryEvents|ImageLoadEvents|LogonEvents|EmailEvents|EmailUrlInfo|EmailAttachmentInfo)|SecurityEvent|SigninLogs|AuditLogs|OfficeActivity|CloudAppEvents|IdentityLogonEvents|ThreatIntelligenceIndicator)\\b)/g;
  const SPL_INDEXES = /\\bindex\\s*=\\s*([a-zA-Z0-9_*-]+)/g;
  for (const q of Object.values(p.queries)) {
    let m;
    while ((m = KQL_TABLES.exec(q))) tablesFound.add(m[0]);
    while ((m = SPL_INDEXES.exec(q))) tablesFound.add('splunk:' + m[1]);
  }
  if (!tablesFound.size) {
    if (/c2|command-and-control/.test(p.uc.ph || '')) tablesFound.add('DeviceNetworkEvents').add('DnsEvents');
    if (/install|persistence/.test(p.uc.ph || '')) tablesFound.add('DeviceProcessEvents').add('DeviceImageLoadEvents');
    if (/exec/.test(p.uc.ph || '')) tablesFound.add('DeviceProcessEvents').add('SecurityEvent');
    if (/cred/.test(p.uc.ph || '')) tablesFound.add('SecurityEvent').add('IdentityLogonEvents');
    if (/exfil/.test(p.uc.ph || '')) tablesFound.add('DeviceNetworkEvents').add('CloudAppEvents');
    if (!tablesFound.size) tablesFound.add('DeviceProcessEvents');
  }
  const dataSources = `<div class="lib-section-body"><ul>${[...tablesFound].map(t => `<li><code>${escapeHtml(t)}</code></li>`).join('')}</ul></div>`;

  const {fp, tune} = _libFpTuning(p);
  const fpHtml = `<div class="lib-section-body"><ul>${fp.map(x => `<li>${x}</li>`).join('')}</ul></div>`;
  const tuneHtml = `<div class="lib-section-body"><ul>${tune.map(x => `<li>${x}</li>`).join('')}</ul></div>`;

  const priority = p.score >= 75 ? 'P1' : p.score >= 55 ? 'P2' : p.score >= 35 ? 'P3' : 'P4';
  const sevLine = `<div class="lib-section-body">
    <p><b>Severity:</b> ${p.sevTag.toUpperCase()} (rolled up from the highest-severity article currently citing this UC).</p>
    <p style="margin-top:6px;"><b>Priority:</b> ${priority} — derived from SOC Value Score ${p.score}/100.</p>
    <p style="margin-top:6px;"><b>Tier:</b> ${escapeHtml(p.uc.tier || 'alerting')}.</p>
  </div>`;

  const recent = p.ucArts.slice(0, 12).map(a => {
    const sev = (a.sev || 'low').toLowerCase();
    const sevCls = ({critical:'crit', crit:'crit', high:'high', medium:'med', med:'med', low:'low'}[sev]) || 'low';
    const src = _libSourceFromArtId(a);
    return `<a class="lib-source-row" href="#article-${escapeHtml(a.id || '')}" onclick="document.getElementById('libDrawer').classList.remove('open');setTimeout(()=>document.getElementById('libDrawer').setAttribute('hidden',''),300);showView('articles');">
      <span class="ls-sev ${sevCls}">${sev}</span>
      <span class="ls-title">${escapeHtml(a.title || '')}</span>
      <span class="ls-src">${escapeHtml(src)}</span>
    </a>`;
  }).join('');
  const more = p.ucArts.length > 12 ? `<div class="lib-empty" style="padding:14px; margin-top:8px;">+ ${p.ucArts.length - 12} more sightings — open the Articles tab to browse.</div>` : '';
  const recentHtml = recent ? `<div class="lib-source-list">${recent}</div>${more}`
                            : `<div class="lib-section-body" style="color:var(--muted);">No recent intel sightings yet — this UC is still in the catalogue but hasn't been triggered by any current article.</div>`;

  const actorsLine = p.actors.length
    ? `<div class="lib-section-body">${p.actors.map(a => `<span class="lib-tag" style="margin-right:6px;">${escapeHtml(a.n)} <span style="opacity:0.65;">· ${escapeHtml(a.c)}</span></span>`).join('')}</div>`
    : '';
  const sourceList = p.sources.length
    ? `<div class="lib-section-body" style="display:flex;flex-wrap:wrap;gap:6px;">${p.sources.map(s => `<span class="lib-tag tactic">${escapeHtml(s)}</span>`).join('')}</div>`
    : '';

  return `
    <div class="lib-detail-head">
      <div class="lib-detail-name">${escapeHtml(p.uc.n)}</div>
      <h2 class="lib-detail-title" id="libDrawerTitle">${escapeHtml(p.uc.t || p.uc.n)}</h2>
      <div class="lib-detail-meta">${sevTag}${tierTag}${phaseTag}${tacticChips}${platTags}</div>
      <div class="lib-detail-svs">
        <div class="lib-detail-svs-score">
          <span class="lib-detail-svs-num">${p.score}</span>
          <span class="lib-detail-svs-label">SOC Value Score</span>
        </div>
        <div class="lib-detail-svs-grid">${svsGrid}</div>
      </div>
    </div>

    <div class="lib-section">
      <h3 class="lib-section-h">Description</h3>
      <div class="lib-section-body">${descIntro}</div>
    </div>

    <div class="lib-section">
      <h3 class="lib-section-h">MITRE ATT&amp;CK Mapping</h3>
      <div class="lib-mitre-grid">${mitre || '<span class="lib-tag">No technique mapping</span>'}</div>
    </div>

    <div class="lib-section">
      <h3 class="lib-section-h">Detection Queries</h3>
      ${havePlats.length ? `<div class="lib-query-tabs">${queryTabs}</div>` : ''}
      ${queryPanes}
    </div>

    <div class="lib-section">
      <h3 class="lib-section-h">Data Sources Required</h3>
      ${dataSources}
    </div>

    <div class="lib-section">
      <h3 class="lib-section-h">False Positives</h3>
      ${fpHtml}
    </div>

    <div class="lib-section">
      <h3 class="lib-section-h">Tuning Advice</h3>
      ${tuneHtml}
    </div>

    <div class="lib-section">
      <h3 class="lib-section-h">Severity &amp; Priority</h3>
      ${sevLine}
    </div>

    ${actorsLine ? `<div class="lib-section">
      <h3 class="lib-section-h">Linked Threat Actors</h3>
      ${actorsLine}
    </div>` : ''}

    <div class="lib-section">
      <h3 class="lib-section-h">Recent Attacks &amp; Sightings</h3>
      ${recentHtml}
    </div>

    ${sourceList ? `<div class="lib-section">
      <h3 class="lib-section-h">Blog Sources</h3>
      ${sourceList}
    </div>` : ''}
  `;
}

// =================================================================
// View tab switching (Articles / ATT&CK Matrix)
// =================================================================
const viewTabs = document.querySelectorAll('.view-tab');
const views = document.querySelectorAll('.view');
function showView(name) {
  viewTabs.forEach(b => b.classList.toggle('active', b.dataset.view === name));
  views.forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  // Each tab has its own top-bar stats area. Body class drives the
  // CSS visibility transition; only the active tab's stats are shown.
  document.body.classList.toggle('view-articles-active', name === 'articles');
  document.body.classList.toggle('view-matrix-active',   name === 'matrix');
  document.body.classList.toggle('view-intel-active',    name === 'intel');
  document.body.classList.toggle('view-actors-active',   name === 'actors');
  document.body.classList.toggle('view-library-active',  name === 'library');
  if (name === 'matrix' && !window._matrixRendered) {
    renderMatrix();
    window._matrixRendered = true;
  }
  if (name === 'intel' && !window._intelRendered) {
    renderIntel();
    window._intelRendered = true;
  }
  if (name === 'actors' && !window._actorsRendered) {
    renderActors();
    window._actorsRendered = true;
  }
  if (name === 'library' && !window._libraryRendered) {
    renderLibrary();
    window._libraryRendered = true;
  }
}
// Apply default state on page load — Articles tab starts active.
document.body.classList.add('view-articles-active');
viewTabs.forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));

// =================================================================
// Welcome banner — permanent strapline. Only thing JS does here is
// wire the "Take the 30-second tour" CTA to startTour(); no dismiss
// logic, no localStorage flag.
// =================================================================
document.getElementById('firstVisitTour')?.addEventListener('click', e => {
  e.preventDefault();
  startTour();
});

// "What's new this week" banner — one-time per user. Bump the version
// string when there are new updates to re-trigger for everyone.
(function whatsNewBanner() {
  const KEY = 'clankerWhatsNew_v2026-W19';
  const el = document.getElementById('whatsnewBanner');
  if (!el) return;
  let dismissed = false;
  try { dismissed = localStorage.getItem(KEY) === '1'; } catch (_) {}
  if (dismissed) return;
  el.hidden = false;
  document.getElementById('whatsnewClose')?.addEventListener('click', () => {
    el.hidden = true;
    try { localStorage.setItem(KEY, '1'); } catch (_) {}
  });
})();

// =================================================================
// Guided tour — switches views, spotlights elements, narrates each.
// Esc skips, ← / → navigate, Enter advances.
// Replay anytime via the "Tour" button in the topbar.
// =================================================================
const TOUR_STEPS = [
  { section: "Articles", view: "articles",
    // Article cards are <article class="card" id="art-XX"> — NOT .article.
    target: "#articles article.card", fallback: "#articles",
    title: "Daily threat-intel feed",
    body: "Each card is a security article auto-pulled from <b>11+ RSS sources</b>, parsed for IOCs and ATT&CK techniques, and enriched with ready-to-deploy detection queries. Refreshes every 2 hours.",
    preview: '<span class="tour-preview-meta">Sources →</span>' +
             '<span class="tour-preview-pill">The Hacker News</span>' +
             '<span class="tour-preview-pill">Bleeping Computer</span>' +
             '<span class="tour-preview-pill">Rapid7</span>' +
             '<span class="tour-preview-pill">CISA KEV</span>' +
             '<span class="tour-preview-pill">+7 more</span>' },
  { section: "Articles", view: "articles",
    target: "#articles article.card details.uc", fallback: "#articles article.card",
    title: "Multi-platform queries on every UC",
    body: "Open any use case to see four detection languages — each with a one-click copy. Sigma rules also pre-compile to Elastic, QRadar, and CrowdStrike at build time.",
    preview: '<span class="tour-preview-pill platform-d">Defender KQL</span>' +
             '<span class="tour-preview-pill platform-s">Sentinel KQL</span>' +
             '<span class="tour-preview-pill platform-z">Sigma</span>' +
             '<span class="tour-preview-pill platform-p">Splunk SPL</span>' },
  { section: "Articles", view: "articles",
    target: "#searchTrigger",
    title: "Search the entire corpus",
    body: "Hit the shortcut (or click the search bar) to filter by technique ID, CVE, severity, or any string in an article body. Indexes 430+ articles and 2,300+ detections.",
    preview: '<span class="tour-preview-key">Ctrl</span>' +
             '<span class="tour-preview-meta">+</span>' +
             '<span class="tour-preview-key">K</span>' +
             '<span class="tour-preview-meta">try:</span>' +
             '<span class="tour-preview-pill">T1059.001</span>' +
             '<span class="tour-preview-pill">CVE-2026-29431</span>' +
             '<span class="tour-preview-pill">lsass</span>' },

  { section: "ATT&CK Matrix", view: "matrix",
    // Spotlight the wrap, NOT #matrixGrid — the grid has overflow-x:auto
    // and a 14×150px = 2,100px min-width, so a position:relative spotlight
    // on the grid disrupts its sticky tactic-headers and shows a punch-
    // hole that extends off-screen. The wrap is viewport-bounded.
    target: ".matrix-wrap", fallback: "#view-matrix",
    title: "Coverage-by-technique heatmap",
    body: "All 14 MITRE tactics, every non-deprecated technique. <b>Cell intensity</b> shows how many of your detections cover that technique. <b>Click any cell</b> for the drawer of UCs and articles.",
    preview: '<span class="tour-preview-meta">222 techniques · 475 sub-techniques · 14 tactics</span>',
    onShow: () => {
      const grid = document.getElementById('matrixGrid');
      if (grid) grid.scrollLeft = 0;
      window.scrollTo({top: document.querySelector('.matrix-toolbar')?.offsetTop - 80 || 0, behavior:'smooth'});
    } },
  { section: "ATT&CK Matrix", view: "matrix",
    target: "#matrixModes", fallback: "#view-matrix .matrix-toolbar",
    title: "Coverage vs Heat — switch the lens",
    body: "<b>Coverage</b> shades cells by how many of your detections fire on that technique. <b>Heat</b> shades them by how many recent articles cite it. <b>All</b> shows both — watch.",
    preview: '<span class="tour-preview-pill">Coverage</span>' +
             '<span class="tour-preview-meta">·</span>' +
             '<span class="tour-preview-pill">Heat</span>' +
             '<span class="tour-preview-meta">·</span>' +
             '<span class="tour-preview-pill">All</span>',
    // Live demo — pause 1 s, click Heat, pause 1 s, click All.
    onShow: (stepIndex) => {
      const click = (sel) => { const b = document.querySelector(sel); if (b) b.click(); };
      const myIndex = stepIndex;
      const stillHere = () => _tourIndex === myIndex;
      setTimeout(() => { if (stillHere()) click('#matrixModes [data-mode="heat"]'); }, 1000);
      setTimeout(() => { if (stillHere()) click('#matrixModes [data-mode="all"]'); }, 2000);
    } },

  { section: "Detection Library", view: "library",
    target: "#libGrid .lib-card", fallback: "#libGrid",
    title: "Every UC, structured.",
    body: "Each card is a full SOC-ready detection page: description, MITRE mapping, queries with copy buttons, data sources, false positives, tuning advice, severity/priority, and recent intel sightings. Click any card for the deep dive.",
    preview: '<span class="tour-preview-pill platform-z">SVS · SOC Value Score</span>' +
             '<span class="tour-preview-meta">composite of</span>' +
             '<span class="tour-preview-pill">Probability</span>' +
             '<span class="tour-preview-pill">Impact</span>' +
             '<span class="tour-preview-pill">Detectability</span>' +
             '<span class="tour-preview-pill">Effort</span>' },
  { section: "Detection Library", view: "library",
    target: "#libFilters", fallback: ".lib-toolbar",
    title: "Filter the way SOC teams actually think",
    body: "Pin to a single platform (<b>Defender / Sentinel / Sigma / Splunk</b>), drill by attack type, threat actor, country of attribution, app/binary mentioned (powershell, lsass, mshta…), severity, or kill-chain phase. Combine freely.",
    preview: '<span class="tour-preview-pill platform-d">Defender</span>' +
             '<span class="tour-preview-pill platform-s">Sentinel</span>' +
             '<span class="tour-preview-pill platform-z">Sigma</span>' +
             '<span class="tour-preview-pill platform-p">Splunk</span>' +
             '<span class="tour-preview-meta">+ phase · actor · country · app</span>' },

  { section: "Threat Intel", view: "intel",
    target: "#view-intel",
    title: "IOC aggregator",
    body: "Every IP, domain, hash, URL, and email mentioned across the article corpus, deduplicated. <b>Filter by type</b>, then export to CSV / JSON / Splunk lookup.",
    preview: '<span class="tour-preview-pill">IPs</span>' +
             '<span class="tour-preview-pill">Domains</span>' +
             '<span class="tour-preview-pill">SHA256</span>' +
             '<span class="tour-preview-pill">URLs</span>' +
             '<span class="tour-preview-meta">→ CSV / JSON / Splunk lookup</span>' },

  { section: "Threat Actors", view: "actors",
    target: "#actorsGlobe", fallback: ".actors-map-wrap",
    title: "187 tracked actors on a 3D globe",
    body: "Every MITRE-tracked APT and e-crime crew, plotted by attribution country on a live WebGL globe. <b>Drag to spin</b>; <b>click any country marker</b> to filter the actor grid below to crews operating from there.",
    preview: '<span class="tour-preview-pill">APT28</span>' +
             '<span class="tour-preview-pill">Lazarus</span>' +
             '<span class="tour-preview-pill">FIN7</span>' +
             '<span class="tour-preview-pill">Volt Typhoon</span>' +
             '<span class="tour-preview-meta">+183 more</span>' },
  { section: "Threat Actors", view: "actors",
    target: ".actor-card", fallback: ".actors-grid",
    title: "Per-actor bespoke detections",
    body: "Each actor card carries detection queries the LLM tailored specifically to that group's known tradecraft — not just a generic technique template.",
    preview: '<span class="tour-preview-meta">e.g.</span>' +
             '<span class="tour-preview-pill">APT28 → INCLUDEPICTURE webhooks</span>' },

  { section: "SOC Cheat Sheet", view: "articles",
    target: ".cheatsheet-btn",
    title: "Analyst-ready query catalogue",
    body: "Opens in a new tab. A curated catalogue of vetted queries, all with copy buttons. Sigma rules compile to KQL, SPL, and Lucene at build time — no toolchain needed on your laptop.",
    preview: '<span class="tour-preview-pill platform-d">96 Defender</span>' +
             '<span class="tour-preview-pill platform-s">56 Sentinel</span>' +
             '<span class="tour-preview-pill platform-z">15 Sigma</span>' },

  { section: "All set", view: "articles", target: null,
    title: "That's the tour.",
    body: "Everything you saw is open source — repo at <b>github.com/Virtualhaggis/usecaseintel</b>. Click the <b>Tour</b> button in the topbar any time to replay.",
    preview: '<span class="tour-preview-meta">★ Star the repo · share the site · ship better detections</span>' }
];

let _tourIndex = 0;

function startTour() {
  _tourIndex = 0;
  document.body.classList.add('tour-on');
  const card = document.getElementById('tourCard');
  if (card) card.hidden = false;
  const prog = document.getElementById('tourProgress');
  if (prog) prog.innerHTML = TOUR_STEPS.map(() => '<span></span>').join('');
  tourGoto(0);
}
function endTour() {
  document.body.classList.remove('tour-on');
  document.querySelectorAll('.tour-spotlight').forEach(el => el.classList.remove('tour-spotlight'));
  const card = document.getElementById('tourCard');
  if (card) card.hidden = true;
}
function _tourSpotlight(target, fallback) {
  document.querySelectorAll('.tour-spotlight').forEach(el => el.classList.remove('tour-spotlight'));
  if (!target) return null;
  let el = document.querySelector(target);
  if (!el && fallback) el = document.querySelector(fallback);
  if (!el) return null;
  // Reject targets whose bounding box is wildly off-screen or absurdly
  // tall — that's the classic "selector matched the wrapper section
  // instead of a single card" failure mode and produces a punch-hole
  // bigger than the viewport.
  const rect = el.getBoundingClientRect();
  if (rect.height > 4000 || rect.width > 4000) return null;
  el.classList.add('tour-spotlight');
  // Scroll target into upper-third of viewport so the bottom-anchored
  // tour card never obscures it. We do this BEFORE measuring for the
  // card-flip so positioning sees the post-scroll rect.
  const viewportH = window.innerHeight;
  if (rect.top < 100 || rect.bottom > viewportH - 280) {
    el.scrollIntoView({behavior: 'smooth', block: 'center'});
  }
  return el;
}
// Retry for lazy-rendered targets (library / actor cards) — the
// view's render function inserts them after a beat.
function _tourSpotlightWithRetry(target, fallback, attempt = 0) {
  const el = _tourSpotlight(target, fallback);
  if (el) return el;
  if (attempt >= 3) return null;
  setTimeout(() => {
    if (_tourIndex < 0) return;
    const e = _tourSpotlightWithRetry(target, fallback, attempt + 1);
    _placeTourCard(e);
  }, 250 * (attempt + 1));
  return null;
}
// Flip the tour card to the top of the viewport when the spotlight
// target sits in the lower half — keeps the card from covering the
// thing it's narrating. Re-checked after scrolling settles.
function _placeTourCard(el) {
  const card = document.getElementById('tourCard');
  if (!card) return;
  if (!el) { card.classList.remove('tour-card-top'); return; }
  const rect = el.getBoundingClientRect();
  const viewportH = window.innerHeight;
  const targetMid = (rect.top + rect.bottom) / 2;
  // If the spotlight midline is in the lower 45% of the viewport,
  // flip the card to the top so it sits above the spotlight.
  card.classList.toggle('tour-card-top', targetMid > viewportH * 0.55);
}
function tourGoto(i) {
  if (i < 0 || i >= TOUR_STEPS.length) return;
  _tourIndex = i;
  const step = TOUR_STEPS[i];
  if (step.view) showView(step.view);
  // Some views need a beat to render before the spotlight can measure
  // their elements — actors mounts a WebGL globe, matrix builds a 222-
  // cell grid. Give those views extra time before scrolling/spotting.
  const needsRender = step.view === 'actors' || step.view === 'matrix' || step.view === 'intel' || step.view === 'library';
  const delay = needsRender ? 480 : 220;
  setTimeout(() => {
    const el = _tourSpotlightWithRetry(step.target, step.fallback);
    _placeTourCard(el);
    setTimeout(() => _placeTourCard(el || document.querySelector('.tour-spotlight')), 380);
    if (typeof step.onShow === 'function') {
      try { step.onShow(i); } catch (_) {}
    }
  }, delay);
  document.getElementById('tourSection').textContent = step.section;
  document.getElementById('tourCounter').textContent = `${i + 1} / ${TOUR_STEPS.length}`;
  document.getElementById('tourCardTitle').textContent = step.title;
  document.getElementById('tourBody').innerHTML = step.body;
  const preview = document.getElementById('tourPreview');
  if (preview) preview.innerHTML = step.preview || '';
  const prog = document.getElementById('tourProgress');
  if (prog) {
    [...prog.children].forEach((dot, idx) => {
      dot.classList.toggle('done', idx < i);
      dot.classList.toggle('active', idx === i);
    });
  }
  const back = document.getElementById('tourBack');
  const next = document.getElementById('tourNext');
  back.disabled = i === 0;
  next.textContent = (i === TOUR_STEPS.length - 1) ? 'Done ✓' : 'Next →';
}
function tourNext() {
  if (_tourIndex >= TOUR_STEPS.length - 1) { endTour(); return; }
  tourGoto(_tourIndex + 1);
}
function tourBack() {
  if (_tourIndex <= 0) return;
  tourGoto(_tourIndex - 1);
}
document.getElementById('tourTrigger')?.addEventListener('click', startTour);
document.getElementById('tourSkip')?.addEventListener('click', endTour);
document.getElementById('tourNext')?.addEventListener('click', tourNext);
document.getElementById('tourBack')?.addEventListener('click', tourBack);
document.getElementById('tourOverlay')?.addEventListener('click', endTour);
document.addEventListener('keydown', e => {
  if (!document.body.classList.contains('tour-on')) return;
  if (e.key === 'Escape') { e.preventDefault(); endTour(); }
  else if (e.key === 'ArrowRight' || e.key === 'Enter') { e.preventDefault(); tourNext(); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); tourBack(); }
});

// =================================================================
// Logo lightbox — click the topbar Clanker to see him full size.
// Backdrop click, ESC, or close-button all dismiss. Re-renders cleanly
// every open (no stale animation state).
// =================================================================
(() => {
  const btn = document.getElementById('logoButton');
  const lb = document.getElementById('logoLightbox');
  const close = document.getElementById('logoLightboxClose');
  if (!btn || !lb) return;
  function open() {
    lb.removeAttribute('hidden');
    lb.classList.add('open');
  }
  function dismiss() {
    lb.classList.remove('open');
    setTimeout(() => lb.setAttribute('hidden', ''), 220);
  }
  btn.addEventListener('click', e => { e.preventDefault(); open(); });
  close.addEventListener('click', dismiss);
  lb.addEventListener('click', e => {
    // Click on the backdrop (not the image itself) closes the lightbox.
    if (e.target === lb) dismiss();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && lb.classList.contains('open')) dismiss();
  });
})();

// =================================================================
// ATT&CK Matrix
// =================================================================
const MATRIX = __MATRIX_DATA__;
let matrixMode = 'coverage';

function covClassFor(n) {
  if (!n) return '';
  if (n >= 4) return 'cov-4';
  if (n >= 3) return 'cov-3';
  if (n >= 2) return 'cov-2';
  return 'cov-1';
}
function heatClassFor(n) {
  if (!n) return '';
  if (n >= 3) return 'heat-3';
  if (n >= 2) return 'heat-2';
  return 'heat-1';
}

function tidCellHtml(tid, isSub) {
  const tinfo = MATRIX.techniques[tid];
  if (!tinfo) return '';
  const ucs = MATRIX.tech_ucs[tid] || [];
  const arts = MATRIX.tech_arts[tid] || [];
  const subCount = (tinfo.subs || []).length;
  let cls = 'tech-cell';
  if (isSub) cls += ' is-sub';
  if (matrixMode === 'coverage') cls += ' ' + covClassFor(ucs.length);
  else if (matrixMode === 'heat') cls += ' ' + heatClassFor(arts.length);
  // Platform-coverage flags — aggregate the `pl` field across every UC
  // attached to this technique. `pl` is now a 5-char string "dsgpD"
  // where each position is the platform letter or '-': d=Defender,
  // s=Sentinel, g=Sigma, p=SPL, D=Datadog. A position is `-` if that
  // UC lacks that platform body. The matrix shows a small badge for
  // each platform that at least one UC on this technique covers.
  let plDef=false, plSent=false, plSigma=false, plSpl=false, plDdog=false;
  for (let u of ucs) {
    const rec = MATRIX.ucs[u];
    if (!rec || !rec.pl) continue;
    if (rec.pl[0] === 'd') plDef = true;
    if (rec.pl[1] === 's') plSent = true;
    if (rec.pl[2] === 'g') plSigma = true;
    if (rec.pl[3] === 'p') plSpl = true;
    if (rec.pl[4] === 'D') plDdog = true;
  }
  const platforms = [];
  if (plDef)   platforms.push('<span class="pl-badge pl-def" title="Defender KQL">D</span>');
  if (plSent)  platforms.push('<span class="pl-badge pl-sent" title="Sentinel KQL">S</span>');
  if (plSigma) platforms.push('<span class="pl-badge pl-sigma" title="Sigma rule">Σ</span>');
  if (plSpl)   platforms.push('<span class="pl-badge pl-spl" title="Splunk SPL">P</span>');
  if (plDdog)  platforms.push('<span class="pl-badge pl-ddog" title="Datadog Cloud SIEM">DD</span>');
  return `<div class="${cls}" data-tid="${tid}" data-pl-def="${plDef?1:0}" data-pl-sent="${plSent?1:0}" data-pl-sigma="${plSigma?1:0}" data-pl-spl="${plSpl?1:0}" data-pl-datadog="${plDdog?1:0}" tabindex="0">
    <div class="tech-name" title="${tid}: ${escapeHtml(tinfo.name)}">${escapeHtml(tinfo.name)}</div>
    <div class="tech-meta">
      <span style="color:var(--muted)">${tid}</span>
      ${subCount ? `<span class="sub-marker">▾${subCount}</span>` : ''}
      ${ucs.length ? `<span class="uc-count">${ucs.length} UC</span>` : ''}
      ${arts.length ? `<span style="color:var(--warn)">${arts.length} art</span>` : ''}
      ${platforms.length ? `<span class="pl-badges">${platforms.join('')}</span>` : ''}
    </div>
  </div>`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
}

function renderMatrix() {
  if (!MATRIX) {
    document.getElementById('matrixGrid').innerHTML =
      '<div style="padding:40px;color:var(--muted);">Matrix data not available — run sync.py to fetch ATT&CK.</div>';
    return;
  }
  const grid = document.getElementById('matrixGrid');
  const cols = MATRIX.tactics.map(tac => {
    const cellsHtml = tac.tids.map(tid => tidCellHtml(tid, false)).join('');
    return `<div class="tactic-col" data-tactic="${tac.short}">
      <div class="tactic-header">
        <span class="tactic-name">${escapeHtml(tac.name)}</span>
        <span class="tactic-count">${tac.tids.length} techniques</span>
      </div>
      <div class="tactic-techs" data-techs>${cellsHtml}</div>
    </div>`;
  }).join('');
  grid.innerHTML = cols;

  // Mirror the matrix counts into the top-bar slot so the stats float
  // up next to the brand the same way the Articles bar does. Same DOM
  // shape as #topStats so the .stat / .v / .l styling kicks in.
  const topMatrix = document.getElementById('topStatsMatrix');
  if (topMatrix) {
    topMatrix.innerHTML =
      `<div class="stat"><div class="v">${MATRIX.stats.total_techs.toLocaleString()}</div><div class="l">Techniques</div></div>` +
      `<div class="stat"><div class="v">${MATRIX.stats.total_subs.toLocaleString()}</div><div class="l">Sub-Techniques</div></div>` +
      `<div class="stat"><div class="v">${MATRIX.stats.covered_techs.toLocaleString()}</div><div class="l">Covered</div></div>` +
      `<div class="stat"><div class="v">${MATRIX.stats.ucs.toLocaleString()}</div><div class="l">Use Cases</div></div>`;
  }
  // Hide the in-tab matrix-stats element since the same numbers now
  // live in the top-bar; redundant on screen.
  const inTabStats = document.getElementById('matrixStats');
  if (inTabStats) inTabStats.style.display = 'none';
}

// Mode toggle
document.getElementById('matrixModes').addEventListener('click', e => {
  const btn = e.target.closest('button');
  if (!btn) return;
  matrixMode = btn.dataset.mode;
  document.querySelectorAll('#matrixModes button').forEach(b => b.classList.toggle('on', b === btn));
  document.querySelectorAll('#matrixGrid .tech-cell').forEach(cell => {
    const tid = cell.dataset.tid;
    const tinfo = MATRIX.techniques[tid];
    cell.classList.remove('cov-1','cov-2','cov-3','cov-4','heat-1','heat-2','heat-3');
    const ucs = MATRIX.tech_ucs[tid] || [];
    const arts = MATRIX.tech_arts[tid] || [];
    if (matrixMode === 'coverage' && ucs.length) cell.classList.add(covClassFor(ucs.length));
    else if (matrixMode === 'heat' && arts.length) cell.classList.add(heatClassFor(arts.length));
  });
});

// Platform-coverage filter (Defender / Sentinel / Sigma / SPL)
let matrixPlatform = 'all';
document.getElementById('matrixPlatforms')?.addEventListener('click', e => {
  const btn = e.target.closest('button');
  if (!btn) return;
  matrixPlatform = btn.dataset.pl;
  document.querySelectorAll('#matrixPlatforms button').forEach(b => b.classList.toggle('on', b === btn));
  document.querySelectorAll('#matrixGrid .tech-cell').forEach(cell => {
    if (matrixPlatform === 'all') {
      cell.classList.remove('pl-filter-dim');
      return;
    }
    const flag = cell.dataset['pl' + matrixPlatform.charAt(0).toUpperCase() + matrixPlatform.slice(1)];
    cell.classList.toggle('pl-filter-dim', flag !== '1');
  });
});

// Search filter
document.getElementById('matrixSearch')?.addEventListener('input', e => {
  const q = e.target.value.trim().toLowerCase();
  document.querySelectorAll('#matrixGrid .tech-cell').forEach(cell => {
    if (!q) { cell.classList.remove('dim'); return; }
    const tid = cell.dataset.tid;
    const tinfo = MATRIX.techniques[tid];
    const match = tid.toLowerCase().includes(q) || tinfo.name.toLowerCase().includes(q);
    cell.classList.toggle('dim', !match);
  });
});

// Cell click → drawer
document.addEventListener('click', e => {
  const cell = e.target.closest('.tech-cell');
  if (!cell) return;
  openDrawerFor(cell.dataset.tid);
});

function openDrawerFor(tid) {
  if (!MATRIX || !MATRIX.techniques[tid]) return;
  // Switch to matrix view if we're not already there
  if (!document.getElementById('view-matrix').classList.contains('active')) {
    showView('matrix');
  }
  const tinfo = MATRIX.techniques[tid];
  const ucs = (MATRIX.tech_ucs[tid] || []).map(i => MATRIX.ucs[i]);
  const arts = (MATRIX.tech_arts[tid] || []).map(i => MATRIX.arts[i]);
  const tactics = (tinfo.tactics || []).map(t => `<span class="tactic-pill">${escapeHtml(t.replace(/-/g,' '))}</span>`).join('');
  const parent = tinfo.parent;
  const parentBlock = parent && MATRIX.techniques[parent]
    ? `<div style="margin-top:10px;font-size:12px;color:var(--muted)">Sub-technique of <a href="#" data-tid="${parent}" class="parent-link" style="color:var(--accent)">${parent} ${escapeHtml(MATRIX.techniques[parent].name)}</a></div>`
    : '';
  document.getElementById('drawerHead').innerHTML = `
    <span class="tid">${tid}</span>
    <h3>${escapeHtml(tinfo.name)}</h3>
    <div class="tactics">${tactics}</div>
    <a class="ext-link" href="https://attack.mitre.org/techniques/${tid.replace('.', '/')}/" target="_blank" rel="noopener">
      View on attack.mitre.org →
    </a>
    ${parentBlock}
  `;
  let body = '';
  // Sub-techniques
  if (tinfo.subs && tinfo.subs.length) {
    body += `<div class="drawer-section"><h4>Sub-techniques (${tinfo.subs.length})</h4><div class="drawer-list">`;
    body += tinfo.subs.map(stid => {
      const stinfo = MATRIX.techniques[stid];
      const stUCs = (MATRIX.tech_ucs[stid] || []).length;
      return `<a href="#" data-tid="${stid}" class="sub-link">
        <div><b>${stid}</b> ${escapeHtml(stinfo.name)}</div>
        <div class="meta">${stUCs ? '<span class="pill">' + stUCs + ' UC</span>' : '<span style="color:var(--muted-2)">no use case</span>'}</div>
      </a>`;
    }).join('');
    body += '</div></div>';
  }
  // Mapped use cases — paginated. With 2150 ESCU detections in the matrix,
  // popular techniques can have hundreds of UCs. Order:
  //   1. LLM-generated article-bespoke UCs (rank-0 — these read the actual
  //      threat-intel article and tailor a detection to the specific TTP)
  //   2. Internal hand-curated UCs
  //   3. Splunk ESCU detections
  // Within each group: alphabetical by title.
  const ucRank = (uc) => {
    if ((uc.t || '').startsWith('[LLM]') || uc.src === 'llm') return 0;
    return uc.src === 'internal' ? 1 : 2;
  };
  const ucsSorted = ucs.slice().sort((a, b) => {
    const ra = ucRank(a), rb = ucRank(b);
    if (ra !== rb) return ra - rb;
    return (a.t || '').localeCompare(b.t || '');
  });
  body += `<div class="drawer-section"><h4>Use cases mapped (${ucs.length})</h4>`;
  if (ucs.length) {
    body += `<div class="drawer-uc-toolbar">
      <input type="text" id="drawerUcSearch" placeholder="Filter use cases…" autocomplete="off">
      <select id="drawerUcSrc">
        <option value="">All sources</option>
        <option value="internal">Internal only</option>
        <option value="escu">Splunk ESCU only</option>
      </select>
      <select id="drawerUcTier">
        <option value="">All tiers</option>
        <option value="alerting">Alerting (high-fidelity)</option>
        <option value="hunting">Hunting (needs tuning)</option>
      </select>
    </div>
    <div class="drawer-list" id="drawerUcList" data-all='${JSON.stringify(ucsSorted).replace(/'/g, "&#39;")}'></div>
    <div class="drawer-uc-pager" id="drawerUcPager" style="display:none;"></div>`;
  } else {
    body += '<div class="drawer-list"><div class="drawer-empty">No use cases reference this technique yet.</div></div>';
  }
  body += '</div>';
  // Articles citing
  body += `<div class="drawer-section"><h4>Articles citing this technique (${arts.length})</h4><div class="drawer-list">`;
  if (arts.length) {
    body += arts.map(art => `<a href="#${art.id}" data-jump="${art.id}" class="art-jump">
      <div>${escapeHtml(art.title)}</div>
      <div class="meta"><span class="pill ${art.sev}">${art.sev.toUpperCase()}</span></div>
    </a>`).join('');
  } else {
    body += '<div class="drawer-empty">No current articles mention this technique.</div>';
  }
  body += '</div></div>';
  document.getElementById('drawerBody').innerHTML = body;
  document.getElementById('techDrawer').classList.add('open');
  document.getElementById('drawerBg').classList.add('open');
  document.getElementById('techDrawer').setAttribute('aria-hidden','false');
  initDrawerUcList();
}

// Render-on-demand UC list inside the drawer. Reads the JSON-encoded
// data-all blob from #drawerUcList, renders 30 at a time with a "load more"
// pager, and wires the search + source-filter inputs.
function initDrawerUcList() {
  const list = document.getElementById('drawerUcList');
  const pager = document.getElementById('drawerUcPager');
  const search = document.getElementById('drawerUcSearch');
  const srcSel = document.getElementById('drawerUcSrc');
  if (!list || !pager) return;
  let allUcs = [];
  try { allUcs = JSON.parse(list.dataset.all); } catch(e) { allUcs = []; }
  let renderedCount = 0;
  const PAGE = 30;
  function ucCardHtml(uc) {
    const artLinks = (uc.arts || []).map(ai => MATRIX.arts[ai] && `<a href="#${MATRIX.arts[ai].id}" data-jump="${MATRIX.arts[ai].id}" class="art-jump" style="color:var(--accent);text-decoration:none;font-size:11px;">→ ${escapeHtml(MATRIX.arts[ai].title.slice(0, 60))}</a>`).filter(Boolean).join('<br>');
    const srcCls = uc.src === 'escu' ? 'escu' : 'internal';
    const srcLabel = uc.src === 'escu' ? 'ESCU' : 'Internal';
    const tier = (uc.tier || 'hunting');
    const tierLabel = tier === 'alerting' ? 'ALERTING' : 'HUNTING';
    return `<div class="uc-card-row tier-${tier}" data-uc-key="${escapeHtml(uc.n)}" data-tier="${tier}" style="padding:8px 10px;background:var(--panel);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;cursor:pointer;">
      <div style="display:flex;align-items:center;gap:8px;">
        <div class="uc-card-title" style="font-weight:600;font-size:12.5px;flex:1;">${escapeHtml(uc.t)}</div>
        <span class="uc-tier-pill ${tier}" title="${tier === 'alerting' ? 'High-fidelity — safe to alert on' : 'Hunting — needs analyst review and tuning'}">${tierLabel}</span>
        <span class="uc-src-pill ${srcCls}">${srcLabel}</span>
        <span class="uc-card-chev" style="color:var(--muted);font-size:11px;">▸</span>
      </div>
      <div class="meta">
        <span class="pill">${escapeHtml(uc.ph || '-')}</span>
        <span class="pill conf${(uc.conf||'').toLowerCase()}">${escapeHtml(uc.conf || '-')}</span>
        <span style="color:var(--muted-2);font-size:10.5px;">${escapeHtml(uc.n)}</span>
      </div>
      ${artLinks ? '<div style="margin-top:6px;line-height:1.4;">' + artLinks + '</div>' : ''}
      <div class="uc-card-detail" style="display:none;"></div>
    </div>`;
  }
  function renderUcDetail(detail) {
    if (!detail) {
      return '<div style="padding:10px;color:var(--muted);font-size:11.5px;">Detection logic not available — sidecar (catalog/use_cases_full.js) is still loading or this UC is missing from it.</div>';
    }
    const techPills = (detail.techniques || []).map(t => {
      const tid = (t && t.id) || t;
      const tname = (t && t.name) || (MATRIX.techniques[tid] && MATRIX.techniques[tid].name) || '';
      return `<span class="pill" style="cursor:pointer;" data-jump-tid="${escapeHtml(tid)}">${escapeHtml(tid)}${tname ? ' ' + escapeHtml(tname) : ''}</span>`;
    }).join(' ');
    const dms = (detail.data_models || []).map(d => `<span class="pill">${escapeHtml(d)}</span>`).join(' ');
    const phPill = detail.kill_chain ? `<span class="pill">${escapeHtml(detail.kill_chain)}</span>` : '';
    let html = `<div style="margin-top:10px;padding-top:10px;border-top:1px dashed var(--border);">`;
    // Tier banner explains alerting vs hunting up-front. Honest framing
    // beats the alternative of users assuming every UC is alert-grade.
    const dt = (detail.tier || 'hunting');
    if (dt === 'alerting') {
      html += `<div style="background:rgba(46,213,99,0.08);border:1px solid rgba(46,213,99,0.35);border-radius:6px;padding:8px 12px;margin-bottom:10px;font-size:11.5px;line-height:1.5;"><b style="color:var(--good);">ALERTING TIER</b> — high-fidelity logic. Specific IOCs, threshold or temporal correlation, or named-binary hunt. Safe to wire to a SIEM rule with normal triage SLA. Still validate with a 7-day backfill in your environment first.</div>`;
    } else {
      html += `<div style="background:rgba(255,176,96,0.08);border:1px solid rgba(255,176,96,0.35);border-radius:6px;padding:8px 12px;margin-bottom:10px;font-size:11.5px;line-height:1.5;"><b style="color:var(--warn);">HUNTING TIER</b> — starter content. Returns rows that need analyst review; will produce false positives without environment tuning. Use as a hunt query first; promote to alerting after baselining + adding suppression for legitimate use.</div>`;
    }
    if (detail.description) {
      html += `<div style="font-size:12px;color:var(--text);opacity:0.92;line-height:1.55;margin-bottom:10px;">${escapeHtml(detail.description)}</div>`;
    }
    // FP-rate + required-telemetry annotations help the SOC decide whether
    // a UC fits their telemetry coverage and noise budget before deploying.
    const fpr = detail.fp_rate_estimate || 'unknown';
    const reqTelem = detail.required_telemetry || [];
    if (fpr !== 'unknown' || reqTelem.length) {
      html += `<div style="display:flex;flex-wrap:wrap;gap:8px;font-size:11px;margin-bottom:10px;">`;
      if (fpr !== 'unknown') {
        const fprColor = {low:'var(--good)', medium:'var(--warn)', high:'var(--bad)'}[fpr] || 'var(--muted)';
        html += `<span style="padding:3px 10px;border-radius:4px;background:var(--panel2);color:${fprColor};border:1px solid var(--border);"><b>FP rate:</b> ${escapeHtml(fpr)}</span>`;
      }
      reqTelem.slice(0, 6).forEach(t => {
        html += `<span style="padding:3px 10px;border-radius:4px;background:var(--panel2);color:var(--muted);border:1px solid var(--border);"><b>Needs:</b> ${escapeHtml(t)}</span>`;
      });
      html += `</div>`;
    }
    if (techPills || phPill || dms) {
      html += `<div class="meta" style="margin-bottom:10px;">${phPill}${techPills}${dms}</div>`;
    }
    if (detail.splunk_spl) {
      html += `<div style="font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;font-weight:600;margin:8px 0 4px 0;">Splunk SPL</div>`;
      html += `<pre style="background:var(--panel-elev);border:1px solid var(--border);border-radius:4px;padding:8px 10px;overflow:auto;font-size:11px;line-height:1.5;color:var(--text);max-height:340px;"><code>${escapeHtml(detail.splunk_spl)}</code></pre>`;
    }
    if (detail.defender_kql) {
      html += `<div style="font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;font-weight:600;margin:8px 0 4px 0;">Defender KQL</div>`;
      html += `<pre style="background:var(--panel-elev);border:1px solid var(--border);border-radius:4px;padding:8px 10px;overflow:auto;font-size:11px;line-height:1.5;color:var(--text);max-height:340px;"><code>${escapeHtml(detail.defender_kql)}</code></pre>`;
    }
    if (detail.source_url) {
      const src = detail.source === 'splunk_escu' ? 'Splunk Security Content (GitHub)' : 'usecaseintel (GitHub)';
      html += `<a href="${escapeHtml(detail.source_url)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:11px;">↗ View source — ${escapeHtml(src)}</a>`;
    }
    html += `</div>`;
    return html;
  }
  function getFiltered() {
    const q = (search?.value || '').trim().toLowerCase();
    const srcF = srcSel?.value || '';
    const tierF = (document.getElementById('drawerUcTier')?.value || '');
    return allUcs.filter(uc => {
      if (srcF && uc.src !== srcF) return false;
      if (tierF && (uc.tier || 'hunting') !== tierF) return false;
      if (!q) return true;
      const blob = ((uc.t || '') + ' ' + (uc.n || '') + ' ' + (uc.techs || []).join(' ')).toLowerCase();
      return blob.includes(q);
    });
  }
  function renderPage(reset) {
    const filtered = getFiltered();
    if (reset) { list.innerHTML = ''; renderedCount = 0; }
    const slice = filtered.slice(renderedCount, renderedCount + PAGE);
    list.insertAdjacentHTML('beforeend', slice.map(ucCardHtml).join(''));
    renderedCount += slice.length;
    const remaining = filtered.length - renderedCount;
    if (remaining > 0) {
      pager.style.display = 'block';
      pager.textContent = `Show next ${Math.min(PAGE, remaining)} (of ${remaining} remaining)`;
    } else {
      pager.style.display = 'none';
    }
  }
  pager.addEventListener('click', () => renderPage(false));
  search?.addEventListener('input', () => renderPage(true));
  srcSel?.addEventListener('change', () => renderPage(true));
  document.getElementById('drawerUcTier')?.addEventListener('change', () => renderPage(true));
  // Click a UC card to expand inline with full SPL/KQL detail.
  list.addEventListener('click', e => {
    // Don't trigger expansion when clicking an embedded link or pill jump
    if (e.target.closest('a, [data-jump-tid]')) return;
    const card = e.target.closest('.uc-card-row');
    if (!card) return;
    const detail = card.querySelector('.uc-card-detail');
    const chev = card.querySelector('.uc-card-chev');
    if (detail.style.display === 'none' || !detail.style.display) {
      const key = card.dataset.ucKey;
      const data = (window.__UC_DETAILS__ || {})[key];
      detail.innerHTML = renderUcDetail(data);
      detail.style.display = '';
      if (chev) chev.textContent = '▾';
      // Wire technique-pill clicks to navigate
      detail.querySelectorAll('[data-jump-tid]').forEach(p => {
        p.addEventListener('click', ev => {
          ev.stopPropagation();
          openDrawerFor(p.dataset.jumpTid);
        });
      });
    } else {
      detail.style.display = 'none';
      if (chev) chev.textContent = '▸';
    }
  });
  renderPage(true);
}

function closeDrawer() {
  document.getElementById('techDrawer').classList.remove('open');
  document.getElementById('drawerBg').classList.remove('open');
  document.getElementById('techDrawer').setAttribute('aria-hidden','true');
}
document.getElementById('drawerClose')?.addEventListener('click', closeDrawer);
document.getElementById('drawerBg')?.addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.getElementById('techDrawer').classList.contains('open')) {
    closeDrawer();
  }
});

// Sub-technique / parent click in drawer
document.getElementById('drawerBody').addEventListener('click', e => {
  const link = e.target.closest('a.sub-link, a.art-jump');
  if (!link) return;
  e.preventDefault();
  const subTid = link.dataset.tid;
  if (subTid) { openDrawerFor(subTid); return; }
  const jump = link.dataset.jump;
  if (jump) {
    closeDrawer();
    showView('articles');
    setTimeout(() => document.getElementById(jump)?.scrollIntoView({behavior:'smooth', block:'start'}), 150);
  }
});
document.getElementById('drawerHead').addEventListener('click', e => {
  const link = e.target.closest('a.parent-link');
  if (!link) return;
  e.preventDefault();
  openDrawerFor(link.dataset.tid);
});

// Make ATT&CK pills in articles deep-link to matrix drawer
document.querySelectorAll('.ind.tech').forEach(pill => {
  const tid = pill.textContent.trim();
  pill.style.cursor = 'pointer';
  pill.title = 'Click to open in ATT&CK Matrix';
  pill.addEventListener('click', e => {
    e.preventDefault(); e.stopPropagation();
    openDrawerFor(tid);
  }, true);
});

// =================================================================
// =================================================================
// Threat Actors tab — rendered on first switch into the tab. Click
// any actor card for a drawer with linked articles, UCs, IOCs.
// Search filters across name + alias + country/region; country chips
// (RU / CN / KP / IR / etc.) further narrow the grid.
// =================================================================
const ACTORS = __ACTORS_DATA__;
let actorsCountryFilter = '';
let actorsMotivationFilter = '';
let actorsSortMode = 'active';

// Approximate lat/lng centroid for each country we attribute actors to.
// The globe library uses {lat, lng} and projects onto the textured
// sphere automatically.
const COUNTRY_LATLNG = {
  RU:{lat:60,  lng:90},   CN:{lat:35,  lng:103},
  KP:{lat:40,  lng:127},  IR:{lat:33,  lng:53},
  IN:{lat:21,  lng:78},   PK:{lat:30,  lng:70},
  VN:{lat:16,  lng:107},  MY:{lat:4,   lng:102},
  LB:{lat:34,  lng:36},   US:{lat:38,  lng:-97},
  BR:{lat:-14, lng:-52}
};

let _globe = null;
let _globePending = false;

function renderActorsMap(filtered) {
  if (typeof Globe === 'undefined') {
    // globe.gl not loaded yet — retry shortly. Defer until the libs
    // finish downloading from the CDN.
    if (!_globePending) {
      _globePending = true;
      const tryAgain = () => {
        if (typeof Globe !== 'undefined') {
          _globePending = false;
          renderActorsMap(filtered);
        } else {
          setTimeout(tryAgain, 200);
        }
      };
      tryAgain();
    }
    return;
  }
  // Aggregate per country
  const byCountry = {};
  filtered.forEach(a => {
    const k = a.country;
    if (!byCountry[k]) byCountry[k] = {count:0, state:0, crim:0, hack:0, names:[]};
    byCountry[k].count++;
    if (a.motivation === 'state') byCountry[k].state++;
    else if (a.motivation === 'criminal') byCountry[k].crim++;
    else if (a.motivation === 'hacktivist') byCountry[k].hack++;
    byCountry[k].names.push(a.name);
  });
  const maxCount = Math.max(1, ...Object.values(byCountry).map(c=>c.count));
  // Build pin data for the globe
  const pins = [];
  Object.entries(byCountry).forEach(([code, info]) => {
    const ll = COUNTRY_LATLNG[code];
    if (!ll) return;  // unknown / "??" actors don't pin to the globe
    const isCrim = info.crim > info.state;
    const isMixed = info.state > 0 && info.crim > 0;
    // Amber for 'mixed' (state + criminal coexist in one country) —
    // distinguishes clearly from the indigo state-only and red
    // criminal-only categories at small pin sizes.
    const color = isMixed ? '#e2a93f' : isCrim ? '#eb5757' : '#7170ff';
    pins.push({
      code, name: COUNTRY_LABELS[code] || code,
      lat: ll.lat, lng: ll.lng,
      count: info.count,
      altitude: 0.06 + (info.count / maxCount) * 0.22,
      radius: 1.4 + (info.count / maxCount) * 2.6,    // chunkier so they're easy to click on a moving globe
      color,
      names: info.names.slice(0, 8).join(', ') + (info.names.length > 8 ? ' +' + (info.names.length - 8) + ' more' : ''),
      isActive: actorsCountryFilter === code
    });
  });
  const container = document.getElementById('actorsGlobe');
  if (!container) return;
  // Build a parallel ring dataset — concentric pulsing rings under
  // each pin make the click target visually larger and animated, so
  // it's obvious where to tap on a slowly-rotating globe.
  const rings = pins.map(p => ({
    lat: p.lat, lng: p.lng,
    color: p.color,
    maxR: 4 + (p.count / maxCount) * 6,
  }));

  if (!_globe) {
    container.innerHTML = '';   // strip the loading placeholder
    _globe = Globe()(container)
      .globeImageUrl('https://unpkg.com/three-globe@2.27.0/example/img/earth-night.jpg')
      .bumpImageUrl('https://unpkg.com/three-globe@2.27.0/example/img/earth-topology.png')
      .backgroundColor('rgba(0,0,0,0)')
      .atmosphereColor('#7170ff')
      .atmosphereAltitude(0.18)
      .pointAltitude('altitude')
      .pointRadius('radius')
      .pointColor('color')
      // Globe.gl Three.js raycaster: bigger pointer-event radius makes
      // pins easier to click even while the globe rotates underneath.
      .pointResolution(8)
      .ringsData(rings)
      .ringColor(d => () => d.color)
      .ringMaxRadius('maxR')
      .ringPropagationSpeed(2)
      .ringRepeatPeriod(1800)
      .ringAltitude(0.005)
      .pointLabel(d => `<div style="background:rgba(15,16,20,0.92); padding:8px 12px; border:1px solid rgba(255,255,255,0.12); border-radius:6px; color:#f7f8f8; font-family:Inter,system-ui; font-size:12px;">
        <div style="font-weight:600; font-size:13px;">${d.name}</div>
        <div style="color:#9b8afb; margin-top:2px;">${d.count} actor${d.count===1?'':'s'}</div>
        <div style="color:#a4a7ad; font-size:10.5px; margin-top:4px; max-width:240px;">${d.names}</div>
      </div>`)
      .onPointClick(d => {
        const newFilter = (actorsCountryFilter === d.code) ? '' : d.code;
        actorsCountryFilter = newFilter;
        document.querySelectorAll('#actorsCountryChips .actors-country-chip').forEach(b => {
          b.classList.toggle('active', (b.dataset.country || '') === newFilter);
        });
        applyActorsFilter();
      })
      .onPointHover(p => {
        if (!_globe.controls || !_globe.controls()) return;
        // Pause auto-rotate when the user is over a pin so clicks land
        _globe.controls().autoRotate = !p;
      })
      .pointsData(pins);
    // Auto-rotate when idle; user interaction (drag) pauses it.
    setTimeout(() => {
      if (_globe.controls && _globe.controls()) {
        _globe.controls().autoRotate = true;
        _globe.controls().autoRotateSpeed = 0.5;
        _globe.controls().enableZoom = true;
        // Pause rotation while the cursor is inside the globe element
        // — gives the user a still target to click. Resume on leave.
        container.addEventListener('mouseenter', () => {
          if (_globe.controls()) _globe.controls().autoRotate = false;
        });
        container.addEventListener('mouseleave', () => {
          if (_globe.controls()) _globe.controls().autoRotate = true;
        });
      }
    }, 100);
    // Resize on viewport change
    const resize = () => {
      if (_globe && container.offsetWidth > 0) {
        _globe.width(container.offsetWidth).height(container.offsetHeight);
      }
    };
    window.addEventListener('resize', resize);
    setTimeout(resize, 50);
  } else {
    _globe.pointsData(pins).ringsData(rings);
  }
}
const COUNTRY_LABELS = {
  RU:"Russia", CN:"China", KP:"North Korea", IR:"Iran",
  US:"United States", BR:"Brazil", IN:"India", PK:"Pakistan",
  VN:"Vietnam", MY:"Malaysia", LB:"Lebanon", "??":"Unknown"
};

// Days between two ISO YYYY-MM-DD strings (returns Infinity if blank)
function _daysSince(iso) {
  if (!iso) return Infinity;
  const d = new Date(iso + 'T00:00:00Z');
  if (isNaN(d.getTime())) return Infinity;
  return (Date.now() - d.getTime()) / 86400000;
}

function renderActors() {
  if (!ACTORS || !ACTORS.length) {
    const grid = document.getElementById('actorsGrid');
    if (grid) grid.innerHTML = '<div class="actors-empty"><p>No threat actors detected in the current article window.</p></div>';
    return;
  }
  // Country chip bar — counts per country, sorted by activity.
  const counts = {};
  ACTORS.forEach(a => { counts[a.country] = (counts[a.country]||0) + 1; });
  const countryOrder = Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([c])=>c);
  const chips = document.getElementById('actorsCountryChips');
  if (chips) {
    chips.innerHTML = '<button class="actors-country-chip active" data-country="">All <span class="cnt">'+ACTORS.length+'</span></button>'
      + countryOrder.map(c =>
          '<button class="actors-country-chip" data-country="'+c+'">'+
          (ACTORS.find(a=>a.country===c)?.flag || '🌐')+' '+
          escapeHtml(COUNTRY_LABELS[c]||c)+
          ' <span class="cnt">'+counts[c]+'</span></button>'
        ).join('');
    chips.querySelectorAll('.actors-country-chip').forEach(b => {
      b.addEventListener('click', () => {
        chips.querySelectorAll('.actors-country-chip').forEach(x => x.classList.remove('active'));
        b.classList.add('active');
        actorsCountryFilter = b.dataset.country;
        applyActorsFilter();
      });
    });
  }
  // Motivation chips
  document.querySelectorAll('#actorsMotChips .actors-country-chip').forEach(b => {
    b.addEventListener('click', () => {
      document.querySelectorAll('#actorsMotChips .actors-country-chip').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      actorsMotivationFilter = b.dataset.mot;
      applyActorsFilter();
    });
  });
  // Sort dropdown
  const sortSel = document.getElementById('actorsSort');
  if (sortSel) sortSel.addEventListener('change', () => {
    actorsSortMode = sortSel.value;
    applyActorsFilter();
  });
  // Clear-filters button — resets country, motivation, search
  document.getElementById('actorsClearFilters')?.addEventListener('click', () => {
    actorsCountryFilter = '';
    actorsMotivationFilter = '';
    const searchEl = document.getElementById('actorsSearch');
    if (searchEl) searchEl.value = '';
    document.querySelectorAll('#actorsCountryChips .actors-country-chip').forEach(b =>
      b.classList.toggle('active', !b.dataset.country));
    document.querySelectorAll('#actorsMotChips .actors-country-chip').forEach(b =>
      b.classList.toggle('active', !b.dataset.mot));
    applyActorsFilter();
  });
  applyActorsFilter();
  document.getElementById('actorsSearch')?.addEventListener('input', applyActorsFilter);
}

// Update the clear-filters button state — count active filters and
// show as a badge so the analyst sees at a glance whether anything
// is filtered. Called from applyActorsFilter on every refresh.
function updateActorsClearBtn() {
  const btn = document.getElementById('actorsClearFilters');
  if (!btn) return;
  const q = (document.getElementById('actorsSearch')?.value || '').trim();
  let n = 0;
  if (actorsCountryFilter) n++;
  if (actorsMotivationFilter) n++;
  if (q) n++;
  btn.disabled = n === 0;
  btn.classList.toggle('has-filters', n > 0);
  const badge = document.getElementById('actorsClearCount');
  if (badge) badge.textContent = n > 0 ? n : '';
}

function applyActorsFilter() {
  const q = (document.getElementById('actorsSearch')?.value || '').toLowerCase().trim();
  let filtered = ACTORS.filter(a => {
    if (actorsCountryFilter && a.country !== actorsCountryFilter) return false;
    if (actorsMotivationFilter && a.motivation !== actorsMotivationFilter) return false;
    if (!q) return true;
    if (a.name.toLowerCase().includes(q)) return true;
    if (a.aliases.some(al => al.toLowerCase().includes(q))) return true;
    if ((COUNTRY_LABELS[a.country]||'').toLowerCase().includes(q)) return true;
    if ((a.country||'').toLowerCase().includes(q)) return true;
    if ((a.motivation||'').toLowerCase().includes(q)) return true;
    if ((a.mitre_id||'').toLowerCase().includes(q)) return true;
    return false;
  });
  // Sort
  filtered.sort((a, b) => {
    if (actorsSortMode === 'recent')  return (b.last_seen||'').localeCompare(a.last_seen||'');
    if (actorsSortMode === 'techs')   return b.techs.length - a.techs.length;
    if (actorsSortMode === 'alpha')   return a.name.localeCompare(b.name);
    return b.articles.length - a.articles.length;   // 'active' default
  });

  // Hero stats
  const totalArticles = filtered.reduce((n,a)=>n+a.articles.length, 0);
  const totalUcs = filtered.reduce((n,a)=>n+a.uc_count, 0);
  const totalLlm = filtered.reduce((n,a)=>n+a.llm_uc_count, 0);
  const totalTechs = new Set();
  filtered.forEach(a => a.techs.forEach(t => totalTechs.add(t)));
  const totalIocs = filtered.reduce((n,a) => n + a.iocs.cves.length + a.iocs.hashes.length + a.iocs.domains.length + a.iocs.ips.length, 0);
  const countries = new Set(filtered.map(a=>a.country));
  const stateCount = filtered.filter(a=>a.motivation==='state').length;
  const crimCount = filtered.filter(a=>a.motivation==='criminal').length;
  // Refresh the clear-filters button enabled/disabled state + badge
  updateActorsClearBtn();
  // Topbar stats — mirrors the .stat shape from #topStats so the
  // existing centred sliding-stats CSS picks it up. Same slot as
  // Articles / Matrix / Intel tabs use.
  const topActors = document.getElementById('topStatsActors');
  if (topActors) {
    topActors.innerHTML =
      `<div class="stat"><div class="v">${filtered.length}</div><div class="l">Actors</div></div>` +
      `<div class="stat"><div class="v">${countries.size}</div><div class="l">Nations</div></div>` +
      `<div class="stat"><div class="v">${totalArticles}</div><div class="l">Articles</div></div>` +
      `<div class="stat"><div class="v">${totalLlm}</div><div class="l">LLM UCs</div></div>` +
      `<div class="stat"><div class="v">${totalTechs.size}</div><div class="l">Techniques</div></div>`;
  }
  // World map dot states refresh on filter change
  if (typeof renderActorsMap === 'function') renderActorsMap(filtered);
  // Reset legacy hero / stats row slots (we now use topbar instead)
  const hero = document.getElementById('actorsHero');
  if (hero) hero.innerHTML = '';
  const stats = document.getElementById('actorsStatsRow');
  if (stats) stats.innerHTML = '';

  const grid = document.getElementById('actorsGrid');
  const empty = document.getElementById('actorsEmpty');
  if (!filtered.length) {
    if (grid) grid.innerHTML = '';
    if (empty) empty.style.display = 'block';
    return;
  }
  if (empty) empty.style.display = 'none';
  if (!grid) return;

  grid.innerHTML = filtered.map(a => {
    const days = _daysSince(a.last_seen);
    let recencyCls = '';
    if (days <= 7) recencyCls = 'recent-7d';
    else if (days <= 30) recencyCls = 'recent-30d';
    const lastSeenLabel = a.last_seen ? a.last_seen + (days<1?' (today)':days<2?' (yesterday)':' ('+Math.floor(days)+' days ago)') : 'Date unknown';
    // Severity bar widths — proportional to article counts
    const total = (a.sev_dist.crit||0)+(a.sev_dist.high||0)+(a.sev_dist.med||0)+(a.sev_dist.low||0) || 1;
    const sevBarHtml = `<div class="ac-sevbar">
      ${a.sev_dist.crit ? `<div class="crit" title="${a.sev_dist.crit} crit" style="flex:${a.sev_dist.crit}"></div>` : ''}
      ${a.sev_dist.high ? `<div class="high" title="${a.sev_dist.high} high" style="flex:${a.sev_dist.high}"></div>` : ''}
      ${a.sev_dist.med  ? `<div class="med"  title="${a.sev_dist.med} med"  style="flex:${a.sev_dist.med}"></div>` : ''}
      ${a.sev_dist.low  ? `<div class="low"  title="${a.sev_dist.low} low"  style="flex:${a.sev_dist.low}"></div>` : ''}
    </div>`;
    const topTechHtml = a.top_techs && a.top_techs.length
      ? `<div class="ac-top-techs">${a.top_techs.map(t=>'<span class="ac-tt">'+escapeHtml(t)+'</span>').join('')}</div>` : '';
    return `
    <div class="actor-card ${recencyCls}" data-name="${escapeHtml(a.name)}">
      <div class="ac-head">
        <span class="ac-flag">${a.flag||'🌐'}</span>
        <div class="ac-title">
          <div class="ac-name">${escapeHtml(a.name)}</div>
          <div class="ac-country">${escapeHtml(COUNTRY_LABELS[a.country]||a.country)}${a.mitre_id ? ' · ' + escapeHtml(a.mitre_id) : ''}</div>
        </div>
        <span class="ac-mot ${a.motivation}">${a.motivation}</span>
      </div>
      <div class="ac-aliases">${escapeHtml(a.aliases.filter(x=>x!==a.name).slice(0,4).join(' · ') || '—')}</div>
      ${topTechHtml}
      ${sevBarHtml}
      <div class="ac-last-seen">Last seen: ${escapeHtml(lastSeenLabel)}</div>
      <div class="ac-stats">
        <div class="ac-stat"><span class="v">${a.articles.length}</span><span class="l">Articles</span></div>
        <div class="ac-stat"><span class="v">${a.uc_count}</span><span class="l">Use cases</span></div>
        <div class="ac-stat"><span class="v">${a.techs.length}</span><span class="l">Techniques</span></div>
      </div>
    </div>`;
  }).join('');
  grid.querySelectorAll('.actor-card').forEach(c =>
    c.addEventListener('click', () => openActorDrawer(c.dataset.name)));
}

// Drawer history stack — lets us push article views on top of the
// actor view so the user can read an article without leaving the
// Threat Actors tab, then "← Back" to the actor or step
// forward/back through the article list inline.
window._actorDrawerStack = [];

function openActorDrawer(name) {
  window._actorDrawerStack = [];
  renderActorView(name);
  document.getElementById('actorDrawer').classList.add('open');
  document.getElementById('actorDrawerBg').classList.add('open');
  document.getElementById('actorDrawer').setAttribute('aria-hidden','false');
}

function renderActorView(name) {
  const a = ACTORS.find(x => x.name === name);
  if (!a) return;
  const body = document.getElementById('actorDrawerBody');
  if (!body) return;
  body.scrollTop = 0;
  // Articles — sort by date desc so latest is first
  const sortedArticles = a.articles.slice().sort((x,y)=>(y.published||'').localeCompare(x.published||''));
  const articleLinks = sortedArticles.map(art =>
    `<a href="#${art.id}" data-jump="${art.id}" class="art-jump">
      <div>${escapeHtml(art.title)}</div>
      <div class="meta">
        ${art.published ? '<span class="pill">'+escapeHtml(art.published)+'</span>' : ''}
        <span class="pill ${art.sev}">${(art.sev||'').toUpperCase()}</span>
      </div>
    </a>`).join('');
  // Techniques as click-pivot pills
  const techPills = a.techs.slice(0,60).map(t =>
    `<span class="ind tech" data-tid-jump="${escapeHtml(t)}" title="Click to open this technique on the ATT&CK matrix">${escapeHtml(t)}</span>`).join(' ');
  // Linked UCs — LLM first, then rule-fired. Click any row to expand
  // it INLINE (accordion) showing the actual SPL/KQL body cloned from
  // the source article card. The articles section below already gives
  // an article-level pivot, so this expansion stays focused on the
  // detection content itself.
  const sortedUcs = a.ucs.slice().sort((x,y)=>(y.is_llm?1:0)-(x.is_llm?1:0));
  const ucList = sortedUcs.length ? `
    <div class="actor-uc-list">
      ${sortedUcs.map((uc, idx) => `
        <details class="actor-uc-row ${uc.is_llm?'is-llm':''}"
                 data-art-id="${uc.art_id}"
                 data-uc-title="${escapeHtml(uc.title)}">
          <summary>
            ${uc.is_llm ? '<span class="uc-llm-pill">LLM</span>' : ''}
            <span class="uc-name">${escapeHtml(uc.title.replace(/^(\[LLM\]\s*)+/, ''))}</span>
            <span class="uc-techs">${(uc.techs||[]).slice(0,3).map(escapeHtml).join(' ')}</span>
            <span class="uc-arrow">▾</span>
          </summary>
          <div class="actor-uc-body" data-loaded="false"></div>
        </details>
      `).join('')}
    </div>` : '<div class="drawer-empty">No linked use cases yet — articles citing this actor didn\'t fire any UC rules or generate LLM-bespoke detections.</div>';
  // Severity bar (drawer-sized)
  const sd = a.sev_dist || {};
  const sevBar = `<div class="actor-drawer-sev">
    ${sd.crit ? `<div class="crit" style="flex:${sd.crit}"></div>` : ''}
    ${sd.high ? `<div class="high" style="flex:${sd.high}"></div>` : ''}
    ${sd.med  ? `<div class="med"  style="flex:${sd.med}"></div>` : ''}
    ${sd.low  ? `<div class="low"  style="flex:${sd.low}"></div>` : ''}
  </div>
  <div style="display:flex; gap:14px; font-size:11.5px; color:var(--muted); margin-bottom:8px;">
    ${sd.crit?'<span style="color:var(--crit)">'+sd.crit+' crit</span>':''}
    ${sd.high?'<span style="color:var(--bad)">'+sd.high+' high</span>':''}
    ${sd.med?'<span style="color:var(--warn)">'+sd.med+' med</span>':''}
    ${sd.low?'<span>'+sd.low+' low</span>':''}
  </div>`;
  const lastSeenDays = _daysSince(a.last_seen);
  const recencyText = !a.last_seen ? 'unknown' :
                      lastSeenDays < 1 ? 'today' :
                      lastSeenDays < 2 ? 'yesterday' :
                      Math.floor(lastSeenDays) + ' days ago';
  body.innerHTML = `
    <div class="drawer-head">
      <h3>${a.flag||'🌐'} ${escapeHtml(a.name)}</h3>
      <div class="drawer-meta">
        <span class="pill">${escapeHtml(COUNTRY_LABELS[a.country]||a.country)}</span>
        <span class="pill">${escapeHtml(a.motivation)}</span>
        ${a.mitre_id ? '<span class="pill"><a href="https://attack.mitre.org/groups/'+escapeHtml(a.mitre_id)+'/" target="_blank" rel="noopener" style="color:inherit;">'+escapeHtml(a.mitre_id)+' ↗</a></span>' : ''}
      </div>
    </div>
    <div class="drawer-section">
      <div class="actor-drawer-dates">
        <span>First seen: <strong>${escapeHtml(a.first_seen||'—')}</strong></span>
        <span>Last seen: <strong>${escapeHtml(a.last_seen||'—')}</strong> (${escapeHtml(recencyText)})</span>
      </div>
      <h4>Severity distribution (${a.articles.length} articles)</h4>
      ${sevBar}
    </div>
    <details class="drawer-section" open>
      <summary>Linked use cases <span class="acc-count">(${a.ucs.length}${a.uc_count > a.ucs.length ? ' shown / ' + a.uc_count + ' total' : ''})</span></summary>
      ${ucList}
    </details>
    <details class="drawer-section" open>
      <summary>ATT&amp;CK techniques observed <span class="acc-count">(${a.techs.length}) — click to pivot to Matrix</span></summary>
      <div style="display:flex; flex-wrap:wrap; gap:6px;">${techPills || '<div class="drawer-empty">None inferred yet.</div>'}</div>
    </details>
    <details class="drawer-section" open>
      <summary>Aliases <span class="acc-count">(${a.aliases.length})</span></summary>
      <div style="font-family:var(--mono); color:var(--muted); font-size:12px; line-height:1.7;">
        ${a.aliases.map(x=>'<span class="ind" style="margin-right:4px;">'+escapeHtml(x)+'</span>').join('')}
      </div>
    </details>
    <details class="drawer-section" open>
      <summary>Articles citing this actor <span class="acc-count">(${a.articles.length})</span></summary>
      <div class="drawer-list">${articleLinks || '<div class="drawer-empty">No articles linked yet.</div>'}</div>
    </details>
    <details class="drawer-section" open>
      <summary>IOCs from linked articles <span class="acc-count">(${a.iocs.cves.length + a.iocs.hashes.length + a.iocs.domains.length + a.iocs.ips.length})</span></summary>
      <div style="font-size:12.5px; color:var(--muted); line-height:1.7;">
        <strong style="color:var(--text);">${a.iocs.cves.length}</strong> CVEs ·
        <strong style="color:var(--text);">${a.iocs.hashes.length}</strong> hashes ·
        <strong style="color:var(--text);">${a.iocs.domains.length}</strong> domains ·
        <strong style="color:var(--text);">${a.iocs.ips.length}</strong> IPs
      </div>
      ${a.iocs.cves.length ? '<div style="margin-top:8px; font-family:var(--mono); font-size:11.5px; color:var(--warn);">'+a.iocs.cves.slice(0,30).map(escapeHtml).join(' · ')+'</div>' : ''}
    </details>
  `;
  // Wire article-jump links — render the article inline inside the
  // drawer (preserves Threat Actors tab focus).
  const articleIds = sortedArticles.map(art => art.id);
  body.querySelectorAll('.art-jump').forEach(el =>
    el.addEventListener('click', e => {
      e.preventDefault();
      const jumpId = el.dataset.jump;
      window._actorDrawerStack.push({type:'actor', name:a.name});
      renderArticleInDrawer(jumpId, articleIds, a.name);
    }));
  // Wire UC accordion rows — first expand lazy-renders the UC body.
  // Three sources of UC body content:
  //   1. Article-bound UC: clone from the source article card DOM.
  //   2. MITRE-derived UC (technique-match, no article): build a
  //      tabbed Defender-KQL / Splunk-SPL view from uc.splunk/uc.kql.
  //   3. UC sidecar lookup (window.__UC_DETAILS__) as fallback for
  //      internal/ESCU detections referenced by name.
  body.querySelectorAll('details.actor-uc-row').forEach((d, idx) => {
    d.addEventListener('toggle', () => {
      if (!d.open) return;
      const panel = d.querySelector('.actor-uc-body');
      if (!panel || panel.dataset.loaded === 'true') return;
      const artId = d.dataset.artId;
      const wantTitle = d.dataset.ucTitle;
      const ucData = sortedUcs[idx] || {};
      // Path 2: embedded SPL/KQL (MITRE-match OR actor-bespoke LLM UC).
      // Render the body straight from the data — no article DOM lookup.
      if (ucData.is_mitre_match || ucData.source_kind === 'actor-bespoke' || ucData.kql || ucData.splunk) {
        const uid = 'auc-' + Math.random().toString(36).slice(2,8);
        let html = '<div class="uc-body" style="padding:14px 16px;">';
        if (ucData.description) {
          html += '<div class="uc-desc" style="color:var(--muted); font-size:12.5px; margin-bottom:10px; line-height:1.55;">' + escapeHtml(ucData.description) + '</div>';
        }
        if (ucData.rationale) {
          html += '<div class="uc-desc" style="color:var(--muted); font-size:12px; margin-bottom:10px; line-height:1.55; padding:8px 12px; background:rgba(113,112,255,0.05); border-left:2px solid var(--accent); border-radius:4px;"><strong style="color:var(--text); font-weight:600;">Why this catches the actor:</strong> ' + escapeHtml(ucData.rationale) + '</div>';
        }
        if (ucData.techs && ucData.techs.length) {
          html += '<div class="uc-meta"><span class="ind-label">ATT&amp;CK</span>' +
            ucData.techs.map(t => '<span class="ind tech">'+escapeHtml(t)+'</span>').join(' ') + '</div>';
        }
        if (ucData.kql || ucData.splunk) {
          html += '<div class="tabs">';
          if (ucData.kql) html += '<button class="tab-btn active" data-target="'+uid+'-kql">Defender KQL</button>';
          if (ucData.splunk) html += '<button class="tab-btn '+(ucData.kql?'':'active')+'" data-target="'+uid+'-spl">Splunk SPL (CIM)</button>';
          html += '</div>';
          if (ucData.kql) html += '<div class="tab-content active" id="'+uid+'-kql"><pre><code>'+escapeHtml(ucData.kql)+'</code></pre></div>';
          if (ucData.splunk) html += '<div class="tab-content '+(ucData.kql?'':'active')+'" id="'+uid+'-spl"><pre><code>'+escapeHtml(ucData.splunk)+'</code></pre></div>';
        } else {
          html += '<div class="drawer-empty">Generic technique match — no SPL/KQL body in catalog yet.</div>';
        }
        html += '</div>';
        panel.innerHTML = html;
        panel.dataset.loaded = 'true';
        return;
      }
      // Path 1: article-bound UC — find <details class="uc"> in source card
      const sourceArt = document.getElementById(artId);
      let target = null;
      if (sourceArt) {
        const all = sourceArt.querySelectorAll('details.uc');
        target = Array.from(all).find(node =>
          (node.querySelector('.uc-title')?.textContent || '').trim() === wantTitle.trim());
      }
      if (target) {
        const innerBody = target.querySelector('.uc-body');
        if (innerBody) {
          panel.appendChild(innerBody.cloneNode(true));
          panel.insertAdjacentHTML('beforeend',
            '<div class="actor-uc-foot"><a href="#" class="actor-uc-srcart" data-jump="'+artId+'">→ Open source article</a></div>');
          panel.querySelector('.actor-uc-srcart')?.addEventListener('click', e => {
            e.preventDefault();
            window._actorDrawerStack.push({type:'actor', name:a.name});
            renderArticleInDrawer(artId, articleIds, a.name);
          });
        } else {
          panel.innerHTML = '<div class="drawer-empty">UC body not available.</div>';
        }
      } else {
        panel.innerHTML = '<div class="drawer-empty">UC body not in current article payload.</div>';
      }
      panel.dataset.loaded = 'true';
    });
  });
  // Tech pill → switch to matrix tab and open that technique drawer
  body.querySelectorAll('[data-tid-jump]').forEach(el =>
    el.addEventListener('click', () => {
      const tid = el.dataset.tidJump;
      closeActorDrawer();
      showView('matrix');
      setTimeout(() => {
        const cell = document.querySelector('#view-matrix [data-tid="' + CSS.escape(tid) + '"]');
        if (cell) cell.click();
      }, 220);
    }));
}
function closeActorDrawer() {
  document.getElementById('actorDrawer')?.classList.remove('open');
  document.getElementById('actorDrawerBg')?.classList.remove('open');
  document.getElementById('actorDrawer')?.setAttribute('aria-hidden','true');
  window._actorDrawerStack = [];
}

// Render an article inline inside the drawer. Clones the source
// .card from the Articles tab so the analyst sees the same kill-
// chain, ATT&CK pills, KQL/SPL queries — without leaving the
// Threat Actors page. Adds a back/forward nav bar at the top.
function renderArticleInDrawer(articleId, siblingIds, actorName) {
  const body = document.getElementById('actorDrawerBody');
  if (!body) return;
  const sourceCard = document.getElementById(articleId);
  if (!sourceCard) {
    body.innerHTML = '<div class="drawer-section"><div class="drawer-empty">Article not found in current page payload.</div></div>';
    return;
  }
  body.scrollTop = 0;
  const idx = siblingIds.indexOf(articleId);
  const prevId = idx > 0 ? siblingIds[idx - 1] : null;
  const nextId = idx >= 0 && idx < siblingIds.length - 1 ? siblingIds[idx + 1] : null;
  // Clone the card so we don't move the original out of the Articles
  // DOM (anchor links to it must still work). Strip the id to avoid
  // duplicate-id warnings while it's parented in the drawer.
  const clone = sourceCard.cloneNode(true);
  clone.removeAttribute('id');
  clone.style.background = 'transparent';
  clone.style.border = 'none';
  clone.style.padding = '0';
  clone.style.borderRadius = '0';
  // Build the drawer with a sticky nav header
  body.innerHTML = `
    <div class="drawer-nav">
      <button class="drawer-nav-btn drawer-nav-back" id="drawerNavBack">← Back to ${escapeHtml(actorName)}</button>
      <div class="drawer-nav-step">
        <button class="drawer-nav-btn" id="drawerNavPrev" ${prevId?'':'disabled'} aria-label="Previous article">‹</button>
        <span class="drawer-nav-pos">${idx + 1} / ${siblingIds.length}</span>
        <button class="drawer-nav-btn" id="drawerNavNext" ${nextId?'':'disabled'} aria-label="Next article">›</button>
      </div>
    </div>
    <div class="drawer-article" id="drawerArticleHost"></div>`;
  document.getElementById('drawerArticleHost').appendChild(clone);
  document.getElementById('drawerNavBack').addEventListener('click', () => {
    const prev = window._actorDrawerStack.pop();
    if (prev && prev.type === 'actor') renderActorView(prev.name);
    else if (actorName) renderActorView(actorName);
  });
  if (prevId) document.getElementById('drawerNavPrev').addEventListener('click', () =>
    renderArticleInDrawer(prevId, siblingIds, actorName));
  if (nextId) document.getElementById('drawerNavNext').addEventListener('click', () =>
    renderArticleInDrawer(nextId, siblingIds, actorName));
}
document.getElementById('actorDrawerClose')?.addEventListener('click', closeActorDrawer);
document.getElementById('actorDrawerBg')?.addEventListener('click', closeActorDrawer);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.getElementById('actorDrawer')?.classList.contains('open')) closeActorDrawer();
});

// =================================================================
// Threat Intel tab
// =================================================================
const INTEL = __INTEL_DATA__;
let intelTypeFilter = '';
let intelSearchQ = '';

const SRC_CLASS = {
  "The Hacker News":"thn", "BleepingComputer":"bc",
  "Microsoft Security Blog":"ms", "CISA KEV":"kev"
};

function renderIntel() {
  if (!INTEL || !INTEL.iocs) return;
  const tbody = document.getElementById('intelBody');
  if (INTEL.iocs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="intel-empty">No IOCs extracted from current article window.</td></tr>';
    return;
  }
  const rows = INTEL.iocs.map((ioc, idx) => {
    const sources = (ioc.sources || []).map(s =>
      `<span class="source-badge ${SRC_CLASS[s] || ''}">${escapeHtml(s)}</span>`).join(' ');
    const a0 = (ioc.articles && ioc.articles[0]) || {title:'', link:'', id:''};
    const more = (ioc.articles || []).length > 1
      ? ` <span style="color:var(--muted-2);font-size:10.5px;">+${ioc.articles.length-1} more</span>` : '';
    return `<tr class="intel-row"
        data-type="${ioc.type}"
        data-search="${escapeHtml((ioc.value+' '+a0.title+' '+(ioc.sources||[]).join(' ')).toLowerCase())}">
      <td><span class="ioc-val ${ioc.type}">${escapeHtml(ioc.value)}</span></td>
      <td><span class="type-pill ${ioc.type}">${ioc.type}</span></td>
      <td><span class="sev-pill ${ioc.severity}">${ioc.severity.toUpperCase()}</span></td>
      <td><div class="sources">${sources}</div></td>
      <td><a class="article-link" href="${escapeHtml(a0.link)}" target="_blank" rel="noopener" title="${escapeHtml(a0.title)}">${escapeHtml(a0.title)}</a>${more}</td>
      <td>${escapeHtml(ioc.first_seen||'')}</td>
      <td><a class="article-link" href="#${a0.id}" data-jump="${a0.id}">view article</a></td>
    </tr>`;
  });
  tbody.innerHTML = rows.join('');
  applyIntelFilter();
  // Wire jump-to-article links
  tbody.querySelectorAll('a[data-jump]').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      showView('articles');
      setTimeout(() => document.getElementById(a.dataset.jump)?.scrollIntoView({behavior:'smooth'}), 100);
    });
  });
}

function applyIntelFilter() {
  let visible = 0;
  const counts = {cve:0, ipv4:0, domain:0, sha256:0, sha1:0, md5:0};
  document.querySelectorAll('#intelBody tr.intel-row').forEach(r => {
    const t = r.dataset.type;
    const blob = r.dataset.search || '';
    const matchType = !intelTypeFilter || t === intelTypeFilter;
    const matchSearch = !intelSearchQ || blob.includes(intelSearchQ);
    const show = matchType && matchSearch;
    r.classList.toggle('dim', !show);
    if (show) visible++;
    if (matchSearch && (t in counts)) counts[t]++;
  });
  const total = INTEL.iocs ? INTEL.iocs.length : 0;
  // In-tab stats — kept hidden because the same numbers are now in the
  // top bar. Left in the DOM in case any other code references it.
  const stats = document.getElementById('intelStats');
  if (stats) {
    stats.innerHTML =
      `<span><b>${visible}</b> of ${total} IOCs</span>` +
      `<span><b>${counts.cve}</b> CVEs</span>` +
      `<span><b>${counts.ipv4}</b> IPs</span>` +
      `<span><b>${counts.domain}</b> domains</span>` +
      `<span><b>${counts.sha256+counts.sha1+counts.md5}</b> hashes</span>`;
    stats.style.display = 'none';
  }
  // Top-bar mirror — same shape as #topStats so the .stat styling kicks in.
  const topIntel = document.getElementById('topStatsIntel');
  if (topIntel) {
    topIntel.innerHTML =
      `<div class="stat"><div class="v">${visible.toLocaleString()}</div><div class="l">Showing</div></div>` +
      `<div class="stat"><div class="v">${total.toLocaleString()}</div><div class="l">Total IOCs</div></div>` +
      `<div class="stat"><div class="v">${counts.cve.toLocaleString()}</div><div class="l">CVEs</div></div>` +
      `<div class="stat"><div class="v">${counts.ipv4.toLocaleString()}</div><div class="l">IPs</div></div>` +
      `<div class="stat"><div class="v">${counts.domain.toLocaleString()}</div><div class="l">Domains</div></div>` +
      `<div class="stat"><div class="v">${(counts.sha256+counts.sha1+counts.md5).toLocaleString()}</div><div class="l">Hashes</div></div>`;
  }
}

document.getElementById('intelTypes')?.addEventListener('click', e => {
  const btn = e.target.closest('button');
  if (!btn) return;
  document.querySelectorAll('#intelTypes button').forEach(b => b.classList.toggle('on', b === btn));
  intelTypeFilter = btn.dataset.type || '';
  applyIntelFilter();
});

document.getElementById('intelSearch')?.addEventListener('input', e => {
  intelSearchQ = e.target.value.trim().toLowerCase();
  applyIntelFilter();
});

// ----- Exports -----
function intelFiltered() {
  return (INTEL.iocs || []).filter(ioc => {
    if (intelTypeFilter && ioc.type !== intelTypeFilter) return false;
    if (intelSearchQ) {
      const blob = (ioc.value + ' ' + (ioc.articles?.[0]?.title || '') + ' ' + (ioc.sources||[]).join(' ')).toLowerCase();
      if (!blob.includes(intelSearchQ)) return false;
    }
    return true;
  });
}

function csvEscape(s) {
  s = String(s ?? '');
  return /[,"\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s;
}

function iocsToCsv(iocs) {
  const head = ['value','type','severity','sources','first_seen','article_titles','article_links','source_count','article_count'];
  const lines = [head.join(',')];
  for (const i of iocs) {
    lines.push([
      i.value, i.type, i.severity,
      (i.sources||[]).join('; '),
      i.first_seen || '',
      (i.articles||[]).map(a => a.title).join('; '),
      (i.articles||[]).map(a => a.link).join('; '),
      (i.sources||[]).length,
      (i.articles||[]).length,
    ].map(csvEscape).join(','));
  }
  return lines.join('\n');
}

function iocsToSplunkLookup(iocs) {
  const head = ['indicator','indicator_type','severity','first_seen','description','source_url'];
  const lines = [head.join(',')];
  for (const i of iocs) {
    const a0 = i.articles?.[0] || {title:'', link:''};
    lines.push([i.value, i.type, i.severity, i.first_seen || '', a0.title, a0.link].map(csvEscape).join(','));
  }
  return lines.join('\n');
}

function stixPattern(t, v) {
  v = v.replace(/'/g,"\\'");
  if (t==='ipv4') return `[ipv4-addr:value = '${v}']`;
  if (t==='domain') return `[domain-name:value = '${v}']`;
  if (t==='sha256') return `[file:hashes.'SHA-256' = '${v}']`;
  if (t==='sha1') return `[file:hashes.'SHA-1' = '${v}']`;
  if (t==='md5') return `[file:hashes.MD5 = '${v}']`;
  if (t==='cve') return `[vulnerability:name = '${v}']`;
  return `[x-custom:value = '${v}']`;
}

function uuid4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random()*16|0;
    return (c==='x' ? r : (r&0x3|0x8)).toString(16);
  });
}

function iocsToStix(iocs) {
  const ts = INTEL.generated || new Date().toISOString();
  return {
    type:'bundle', id:'bundle--'+uuid4(),
    objects: iocs.map(i => ({
      type:'indicator', spec_version:'2.1',
      id:'indicator--'+uuid4(),
      created:ts, modified:ts, valid_from:ts,
      name: i.type.toUpperCase()+': '+i.value,
      pattern: stixPattern(i.type, i.value), pattern_type:'stix',
      labels:['malicious-activity'],
      external_references: (i.articles||[]).slice(0,3).map(a => ({source_name:(a.title||'').slice(0,60), url:a.link})),
      x_severity: i.severity,
      x_sources: i.sources || [],
    }))
  };
}

function downloadFile(name, content, mime) {
  const blob = new Blob([content], {type:mime||'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 300);
}

document.querySelectorAll('button[data-export]').forEach(btn => {
  btn.addEventListener('click', () => {
    const data = intelFiltered();
    const stamp = new Date().toISOString().slice(0,10);
    const kind = btn.dataset.export;
    if (kind === 'csv') {
      downloadFile(`iocs-${stamp}.csv`, iocsToCsv(data), 'text/csv');
    } else if (kind === 'json') {
      downloadFile(`iocs-${stamp}.json`,
        JSON.stringify({generated: INTEL.generated, count: data.length, iocs: data}, null, 2),
        'application/json');
    } else if (kind === 'stix') {
      downloadFile(`iocs-${stamp}.stix.json`, JSON.stringify(iocsToStix(data), null, 2), 'application/json');
    } else if (kind === 'splunk') {
      downloadFile(`splunk_lookup_iocs-${stamp}.csv`, iocsToSplunkLookup(data), 'text/csv');
    } else if (kind === 'copy') {
      navigator.clipboard.writeText(iocsToCsv(data)).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = orig, 1300);
      });
    }
  });
});
</script>
<!-- 3D globe libraries — three.js + globe.gl from unpkg. Loaded with
     defer so they never block the page; the globe renders only once
     the user opens the Threat Actors tab. If the CDN fails the rest
     of the site still works (the country chips and grid are
     independent). -->
<script defer src="https://unpkg.com/three@0.150.1/build/three.min.js"></script>
<script defer src="https://unpkg.com/globe.gl@2.27.0/dist/globe.gl.min.js"></script>
<!-- Share & deeplink routing.
     Hash format:
       #uc-<10hex>           open + scroll to a use case
       #article-<date>-<slug> scroll to an article card
     The Copy-link buttons hand out share-stub URLs (share/uc/<slug>.html
     or share/article/<slug>.html) so chat-app unfurls (Discord/Slack/X)
     get proper og:* previews; the stub redirects humans to the in-app
     hash URL in <50 ms. -->
<script>
(function(){
  function shareStubUrl(kind, slug){
    var base = location.origin + location.pathname.replace(/\/index\.html$/, '/');
    if (!base.endsWith('/')) base += '/';
    return base + 'share/' + kind + '/' + encodeURIComponent(slug) + '.html';
  }
  function highlight(el){
    if (!el) return;
    el.classList.add('deeplink-target');
    setTimeout(function(){ el.classList.remove('deeplink-target'); }, 1700);
  }
  function openUc(slug){
    var el = document.querySelector('[data-uc-slug="' + slug.replace(/"/g, '\\"') + '"]');
    if (!el) return false;
    var p = el;
    while (p) {
      if (p.tagName === 'DETAILS' && !p.open) p.open = true;
      p = p.parentElement;
    }
    el.scrollIntoView({behavior:'smooth', block:'center'});
    highlight(el);
    var t = el.querySelector('.uc-title');
    if (t) document.title = t.textContent.trim() + ' · Clankerusecase';
    return true;
  }
  function openArticle(slug){
    var el = document.querySelector('[data-art-slug="' + slug.replace(/"/g, '\\"') + '"]');
    if (!el) return false;
    el.scrollIntoView({behavior:'smooth', block:'start'});
    highlight(el);
    var t = el.querySelector('h2 a, h2');
    if (t) document.title = t.textContent.trim() + ' · Clankerusecase';
    return true;
  }
  function route(hash){
    if (!hash) return false;
    hash = hash.replace(/^#/, '');
    var m;
    if ((m = hash.match(/^uc-([0-9a-f]+)$/i))) return openUc(m[1]);
    if ((m = hash.match(/^article-(.+)$/))) return openArticle(decodeURIComponent(m[1]));
    return false;
  }
  function initialRoute(){
    if (!location.hash) return;
    var tries = 0;
    var iv = setInterval(function(){
      if (route(location.hash) || ++tries > 25) clearInterval(iv);
    }, 150);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialRoute);
  } else {
    initialRoute();
  }
  window.addEventListener('hashchange', function(){ route(location.hash); });

  // Copy-link click handler. Uses the share-stub URL by default so
  // chat-app unfurls work; falls back to the hash URL if Shift is held.
  document.addEventListener('click', function(e){
    var btn = e.target.closest('[data-share-uc], [data-share-art]');
    if (!btn) return;
    e.preventDefault(); e.stopPropagation();
    var slug = btn.getAttribute('data-share-uc') || btn.getAttribute('data-share-art');
    var kind = btn.hasAttribute('data-share-uc') ? 'uc' : 'article';
    var url;
    if (e.shiftKey) {
      var base = location.origin + location.pathname.replace(/\/index\.html$/, '/');
      url = base + '#' + kind + '-' + slug;
    } else {
      url = shareStubUrl(kind, slug);
    }
    var ta = document.createElement('textarea');
    ta.value = url; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch(_){}
    document.body.removeChild(ta);
    if (!ok && navigator.clipboard) navigator.clipboard.writeText(url).catch(function(){});
    btn.classList.add('copied');
    setTimeout(function(){ btn.classList.remove('copied'); }, 1200);
  });
})();
</script>

<!-- Cloudflare Web Analytics — privacy-friendly, no cookies, no GDPR
     banner needed. Beacon script is loaded with `defer` so it never
     blocks the 8 MB index.html parse, and it's injected at the very
     end of <body> so analytics never get in the way of content load. -->
<script defer src='https://static.cloudflareinsights.com/beacon.min.js' data-cf-beacon='{"token": "93e5a6361d834ae2b95d7a90b539fe71"}'></script>
</body>
</html>
"""


def compute_severity(article_text: str, ind: dict, ucs: list, techs: list) -> str:
    """Return 'crit' | 'high' | 'med' | 'low' based on signals."""
    t = article_text.lower()
    score = 0
    if ind["cves"]:
        score += 2
    if any(k in t for k in ("zero-day", "0-day", "zero day", "actively exploited",
                              "kev", "in the wild", "supply chain", "supply-chain",
                              "ransomware", "wiper", "rce", "remote code execution")):
        score += 3
    if any(k in t for k in ("apt", "lazarus", "kimsuky", "fin7", "scattered spider",
                              "volt typhoon", "salt typhoon", "tropic trooper",
                              "muddywater", "fancy bear", "cozy bear", "cobalt strike",
                              "lockbit", "blackcat", "alphv", "akira", "rhysida",
                              "ransomhub", "qilin", "play ransomware")):
        score += 2
    score += min(len(ucs), 3)
    score += min(len(techs) // 3, 2)

    if score >= 9: return "crit"
    if score >= 6: return "high"
    if score >= 3: return "med"
    return "low"


SEV_LABEL = {"crit": "Critical", "high": "High", "med": "Medium", "low": "Low"}


# =============================================================================
# Splunk SPL — accelerated (summarised) vs non-accelerated variant
# =============================================================================
# CIM data-model acceleration is environment-dependent. Plenty of SOCs run
# Splunk without acceleration enabled, so a `tstats summariesonly=true` query
# would return zero rows for them. We emit both forms when applicable: the
# fast accelerated query (default) plus an auto-derived non-accelerated
# variant that runs against raw data without needing the summary index.

def _spl_make_unsummarised(spl: str) -> str:
    """Convert an accelerated tstats query to the non-accelerated form.
    Strategy:
      1. Replace the `summariesonly` macro with `summariesonly=false`.
      2. Replace explicit `summariesonly=true|t|1` with `summariesonly=false`.
      3. If the tstats invocation has no summariesonly arg at all, add it.
    Returns the original query unchanged when there's no tstats / nothing
    to convert."""
    if not spl:
        return spl
    if "tstats" not in spl.lower():
        return spl  # raw `search index=...` queries already work without acceleration
    out = spl
    # Pattern 1: `summariesonly` macro
    out = re.sub(r"`summariesonly`", "summariesonly=false", out)
    # Pattern 2: literal summariesonly=true|t|1
    out = re.sub(r"\bsummariesonly\s*=\s*(?:true|t|1|yes|y)\b",
                  "summariesonly=false", out, flags=re.IGNORECASE)
    # Pattern 3: tstats with no summariesonly arg at all — inject one right after `tstats`
    if not re.search(r"\bsummariesonly\s*=", out, flags=re.IGNORECASE):
        out = re.sub(r"(\|\s*tstats\b)(\s+)",
                      r"\1 summariesonly=false\2", out, count=1, flags=re.IGNORECASE)
    return out


def _spl_has_dual_form(spl: str) -> bool:
    """True when the query has both an accelerated and non-accelerated
    representation worth showing as a toggle."""
    if not spl:
        return False
    alt = _spl_make_unsummarised(spl)
    return alt != spl


def render_indicators(ind: dict, techniques: list) -> str:
    out = []
    def block(label, items, cls=""):
        if not items: return ""
        chips = " ".join(f'<span class="ind {cls}">{html.escape(str(i))}</span>' for i in items)
        return f'<div class="ind-group"><span class="ind-label">{label}</span>{chips}</div>'

    out.append(block("CVEs", ind["cves"], "cve"))
    if techniques:
        chips = " ".join(
            f'<span class="ind tech" title="{html.escape(name)}">{html.escape(tid)}</span>'
            for tid, name in techniques[:14]
        )
        out.append(f'<div class="ind-group"><span class="ind-label">ATT&amp;CK</span>{chips}</div>')
    out.append(block("Domains", ind["domains"][:10]))
    out.append(block("IPs", ind["ips"]))
    if ind["sha256"]: out.append(block("SHA256", [h[:16] + "…" for h in ind["sha256"][:5]]))
    if ind["sha1"]: out.append(block("SHA1", [h[:16] + "…" for h in ind["sha1"][:5]]))
    if ind["md5"]: out.append(block("MD5", [h[:16] + "…" for h in ind["md5"][:5]]))
    return "\n".join(b for b in out if b)


def render_killchain(art_id: str, hit: set, inferred: set,
                     uc_by_phase: dict) -> str:
    cells = []
    detail_lines = []
    for i, (pid, name, descr) in enumerate(KILL_CHAIN_PHASES):
        cls, marker = "", "—"
        if pid in hit:
            cls, marker = "hit", "Detected"
        elif pid in inferred:
            cls, marker = "inferred", "Likely"
        cells.append(f'''<div class="kc-cell {cls}">
  <div class="num">Phase {i+1}</div>
  <div class="name">{html.escape(name)}</div>
  <div class="marker">{marker}</div>
</div>''')
        ucs_here = uc_by_phase.get(pid, [])
        line_cls = "hit" if pid in hit else ("inferred" if pid in inferred else "")
        descr_html = html.escape(descr)
        if ucs_here:
            uc_titles = " · ".join(html.escape(u.title) for u in ucs_here)
            descr_html += f' <em>→ {uc_titles}</em>'
        detail_lines.append(
            f'<div class="phase-line {line_cls}"><strong>{html.escape(name)}.</strong> {descr_html}</div>'
        )
    track = "\n".join(cells)
    detail = "\n".join(detail_lines)
    return f"""
<div class="killchain" id="{art_id}-kc">
  <div class="kc3d">{track}</div>
  <div class="kc-detail">{detail}</div>
</div>
""".strip()


def render_use_case(art_id: str, idx: int, uc: UseCase, ind: dict) -> str:
    spl = parameterize(uc.splunk_spl, ind)
    kql = parameterize(uc.defender_kql, ind)
    skql = parameterize(uc.sentinel_kql, ind) if uc.sentinel_kql else ""
    sigma = uc.sigma_yaml or ""        # Sigma rules don't take parameter substitution
    ddog = parameterize(uc.datadog_query, ind) if uc.datadog_query else ""
    techs = " ".join(
        f'<span class="ind tech" title="{html.escape(name)}">{html.escape(tid)}</span>'
        for tid, name in uc.techniques
    )
    dms = " ".join(
        f'<span class="ind">{html.escape(d)}</span>' for d in uc.data_models
    )
    uid = f"{art_id}-uc{idx}"
    phase_name = next((n for p, n, _ in KILL_CHAIN_PHASES if p == uc.kill_chain), uc.kill_chain)
    conf_cls = uc.confidence.lower()
    # Build tabs dynamically — every platform is conditional. The LLM legitimately
    # produces UCs with NO Defender KQL (e.g. CDN-level DDoS where the relevant
    # telemetry is web-server / Sentinel logs, not endpoint events). Hard-coding
    # Defender as the always-active tab left those UCs displaying an empty body.
    # First non-empty platform becomes the active one; tabs render in canonical
    # order: Defender → Sentinel → Sigma → Datadog → Splunk.
    platforms = [
        ("kql",      "Defender KQL",     kql),
        ("sentinel", "Sentinel KQL",     skql),
        ("sigma",    "Sigma",            sigma),
        ("datadog",  "Datadog",          ddog),
        ("spl",      "Splunk SPL (CIM)", spl),
    ]
    populated = [(suffix, label, body) for suffix, label, body in platforms if body]
    if not populated:
        # Edge case: UC has no platform body at all. Render an explanatory
        # placeholder so the UC still appears (with its title + ATT&CK) but
        # the absence is obvious to analysts.
        tab_btns = ""
        tab_panes = '<div class="tab-content active"><div style="padding:14px 0;color:var(--muted);font-size:12.5px;">No platform-specific query body emitted for this UC. The mapped MITRE techniques and data sources above can be used to look up an equivalent detection in your SIEM.</div></div>'
    else:
        tab_btns = "\n      ".join(
            f'<button class="tab-btn{" active" if i == 0 else ""}" data-target="{uid}-{suffix}">{label}</button>'
            for i, (suffix, label, _) in enumerate(populated)
        )
        # Splunk SPL gets a nested Summarised/Non-summarised toggle when the
        # tstats-form has a non-accelerated variant. The toggle is purely
        # client-side; the canonical body stays the accelerated one so any
        # downstream consumer (rule_packs export, drawer scrape) still picks
        # up the same SPL it always did.
        def _pane_body(suffix: str, body: str) -> str:
            if suffix == "spl" and _spl_has_dual_form(body):
                alt = _spl_make_unsummarised(body)
                # Wrapped in .spl-toggle-group so the global click handler
                # can scope the toggle to this pair of buttons + bodies even
                # when the surface (article card vs Library drawer) differs.
                return (
                    f'<div class="spl-toggle-group">'
                    f'<div class="spl-mode-toggle">'
                    f'  <button class="spl-mode-btn active" data-spl-mode="acc" data-target="{uid}-spl-acc">Summarised</button>'
                    f'  <button class="spl-mode-btn" data-spl-mode="raw" data-target="{uid}-spl-raw">Non-summarised</button>'
                    f'  <span class="spl-mode-hint">Toggle if your env has no CIM data-model acceleration.</span>'
                    f'</div>'
                    f'<pre class="spl-mode-body active" id="{uid}-spl-acc">'
                    f'<button class="copy-btn">COPY</button><code>{html.escape(body)}</code></pre>'
                    f'<pre class="spl-mode-body" id="{uid}-spl-raw">'
                    f'<button class="copy-btn">COPY</button><code>{html.escape(alt)}</code></pre>'
                    f'</div>'
                )
            return (
                f'<pre><button class="copy-btn">COPY</button>'
                f'<code>{html.escape(body)}</code></pre>'
            )
        tab_panes = "\n    ".join(
            f'<div class="tab-content{" active" if i == 0 else ""}" id="{uid}-{suffix}">'
            f'{_pane_body(suffix, body)}'
            f'</div>'
            for i, (suffix, _, body) in enumerate(populated)
        )
    uslug = _uc_slug(uc)
    # data-platforms drives the Articles-tab Platform filter: when the
    # user picks Datadog, the JS hides UCs on the visible article cards
    # that don't have a Datadog query body, so they get a clean view of
    # only the platform they selected.
    uc_plats = ",".join(sorted({
        p for p in [
            ("def" if uc.defender_kql else None),
            ("sent" if uc.sentinel_kql else None),
            ("sigma" if getattr(uc, "sigma_yaml", "") else None),
            ("spl" if uc.splunk_spl else None),
            ("datadog" if getattr(uc, "datadog_query", "") else None),
        ] if p
    }))
    # Target-surface tags (windows/linux/aws/...) — drives the Articles-tab
    # Target filter chips. Inferred from the actual query bodies so a
    # CloudTrail / cloudtrail-tagged UC light up the AWS chip even when the
    # article title is generic.
    uc_targets_attr = ",".join(_infer_uc_targets(uc))
    return f"""
<details class="uc" data-uc-slug="{uslug}" data-platforms="{uc_plats}" data-targets="{uc_targets_attr}"{ ' open' if idx == 0 else '' }>
  <summary>
    <span class="uc-title">{html.escape(uc.title)}</span>
    <span class="uc-phase">{html.escape(phase_name)}</span>
    <span class="uc-conf {conf_cls}">{html.escape(uc.confidence)}</span>
    <button class="share-btn" data-share-uc="{uslug}" title="Copy share link to this UC" aria-label="Copy share link">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
    </button>
  </summary>
  <div class="uc-body">
    <div class="uc-desc">{html.escape(uc.description)}</div>
    <div class="uc-meta"><span class="ind-label">ATT&amp;CK</span>{techs}</div>
    <div class="uc-meta"><span class="ind-label">Data sources</span>{dms}</div>
    <div class="tabs">
      {tab_btns}
    </div>
    {tab_panes}
  </div>
</details>
""".strip()


def render_card(idx: int, article: dict, ind: dict,
                techniques: list, hit: set, inferred: set,
                use_cases: list, severity: str) -> str:
    aid = f"art-{idx:02d}"
    pubmeta = html.escape(article.get("published", ""))
    summary = html.escape(article.get("summary", ""))
    indicators_html = render_indicators(ind, techniques)
    # LLM-driven article-bespoke UCs (titles prefixed `[LLM]`) read the
    # actual threat-intel article and tailor a detection to the specific
    # TTP, so they're the highest-fidelity items on the card. Sort them
    # to the top of the per-article use-case list, then everything else
    # in the order rules fired them.
    use_cases = sorted(
        use_cases,
        key=lambda u: 0 if (u.title or "").startswith("[LLM]") else 1,
    )
    uc_by_phase = {}
    for uc in use_cases:
        uc_by_phase.setdefault(uc.kill_chain, []).append(uc)
    killchain_html = render_killchain(aid, hit, inferred, uc_by_phase)
    uc_html = "\n".join(render_use_case(aid, i, uc, ind) for i, uc in enumerate(use_cases))

    phases_attr = ",".join(sorted(hit | inferred))
    techs_attr = ",".join(t for t, _ in techniques)
    search_blob = " ".join([
        article["title"], article.get("summary", ""),
        " ".join(ind["cves"]),
        " ".join(t for t, _ in techniques),
        " ".join(uc.title for uc in use_cases),
    ])

    src_class_map = {
        "The Hacker News": "thn",
        "BleepingComputer": "bc",
        "Microsoft Security Blog": "ms",
        "CISA KEV": "kev",
        "Cisco Talos": "talos",
        "Securelist (Kaspersky)": "securelist",
        "SentinelLabs": "sentinel",
        "Unit 42 (Palo Alto)": "unit42",
        "ESET WeLiveSecurity": "eset",
        "Lab52": "lab52",
        "Cyber Security News": "csn",
    }
    sources = article.get("sources") or [article.get("source", "")]
    source_html = "".join(
        f'<span class="source-badge {src_class_map.get(s, "")}">{html.escape(s)}</span>'
        for s in sources if s
    )
    sources_attr = "|".join(sources)
    # Counts power the "Has UCs" / "Has LLM UCs" feature filters in the
    # toolbar. data-uc-count is total UCs on this card; data-llm-uc-count
    # is the subset whose title starts with "[LLM]" (the article-bespoke
    # ones the LLM tailored to the specific TTP).
    uc_total = len(use_cases)
    uc_llm = sum(1 for u in use_cases if (u.title or "").startswith("[LLM]"))
    art_slug = _art_slug(article, article.get("published", ""))
    # Platforms covered by ANY UC on this card — drives the Platform filter
    # chip group on the toolbar so analysts can find e.g. "every article that
    # has a Datadog query".
    plats = set()
    for uc in use_cases:
        if uc.defender_kql: plats.add("def")
        if uc.sentinel_kql: plats.add("sent")
        if getattr(uc, "sigma_yaml", ""): plats.add("sigma")
        if uc.splunk_spl: plats.add("spl")
        if getattr(uc, "datadog_query", ""): plats.add("datadog")
    plats_attr = ",".join(sorted(plats))
    # Card-level target-surface attribute — union of every UC's targets on
    # the card. Drives the Articles-tab Target chip group.
    targets_set: set = set()
    for uc in use_cases:
        for tg in _infer_uc_targets(uc):
            targets_set.add(tg)
    targets_attr = ",".join(sorted(targets_set))
    return f"""
<article class="card" id="{aid}" data-art-slug="{html.escape(art_slug)}"
  data-phases="{phases_attr}" data-sev="{severity}"
  data-techs="{html.escape(techs_attr)}"
  data-sources="{html.escape(sources_attr)}"
  data-platforms="{plats_attr}"
  data-targets="{targets_attr}"
  data-uc-count="{uc_total}" data-llm-uc-count="{uc_llm}"
  data-search="{html.escape(search_blob)}">
  <div class="sev-ribbon {severity}">{SEV_LABEL[severity]}</div>
  <button class="share-btn card-share" data-share-art="{html.escape(art_slug)}" title="Copy share link to this article" aria-label="Copy share link">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
  </button>
  <h2><a href="{html.escape(article['link'])}" target="_blank" rel="noopener">{html.escape(article['title'])}</a></h2>
  <div class="source-badges">{source_html}</div>
  <div class="pubmeta">
    <span>{pubmeta}</span>
    <span>{len(use_cases)} use case{'s' if len(use_cases)!=1 else ''}</span>
    <span>{len(techniques)} technique{'s' if len(techniques)!=1 else ''}</span>
    <span>{len(hit)} kill-chain phase{'s' if len(hit)!=1 else ''} detected</span>
  </div>
  <p class="summary">{summary}</p>
  {indicators_html}
  <div class="action-row">
    <button class="btn btn-kc" data-target="{aid}-kc"><svg class="kc-chev" width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 4.5 6 7.5 9 4.5"/></svg><span class="kc-label">Show kill chain</span></button>
    <span class="btn-meta">Click any ATT&amp;CK pill below to open it on the Matrix</span>
  </div>
  {killchain_html}
  <div class="usecases">{uc_html}</div>
</article>
""".strip()


def render_nav(articles_meta):
    items = []
    for i, m in enumerate(articles_meta, start=1):
        aid = f"art-{i-1:02d}"
        title = html.escape(m["title"])
        sev = m["sev"]
        items.append(
            f'<div class="nav-item" data-jump="{aid}">'
            f'<span class="num">{i:02d}</span>'
            f'<span class="ttl">{title}</span>'
            f'<span class="sev {sev}"></span>'
            f'</div>'
        )
    return "\n".join(items)


def render_filter_chips() -> str:
    chips = []
    for sev_key, sev_lbl in [("crit", "Critical"), ("high", "High"), ("med", "Medium"), ("low", "Low")]:
        chips.append(f'<button class="fchip" data-key="sev" data-val="{sev_key}"><span class="dot"></span>{sev_lbl}<span class="x">×</span></button>')
    chips.append('<span style="width:1px;height:18px;background:var(--border);margin:0 6px;"></span>')
    for pid, name, _ in KILL_CHAIN_PHASES:
        chips.append(f'<button class="fchip" data-key="phase" data-val="{pid}">{html.escape(name)}<span class="x">×</span></button>')
    return "\n".join(chips)


# =============================================================================
# ATT&CK Matrix data — designed for 10,000+ use cases (lean refs, no inline)
# =============================================================================

# Canonical ATT&CK Enterprise tactic order (left-to-right)
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]
TACTIC_DISPLAY = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

REGISTRY_PATH_FOR_MATRIX = Path(__file__).parent / "data_sources" / "registry.json"


def _load_attack_data():
    """Read MITRE ATT&CK techniques + tactics from registry.json."""
    if not REGISTRY_PATH_FOR_MATRIX.exists():
        return None
    try:
        return __import__("json").loads(REGISTRY_PATH_FOR_MATRIX.read_text(encoding="utf-8"))
    except Exception:
        return None


# =============================================================================
# Target-surface inference — what asset / OS / cloud does this UC apply to?
# =============================================================================
# This is the OS / cloud / SaaS axis ("Linux", "Windows", "AWS", "Kubernetes")
# distinct from the SIEM / EDR axis ("Defender", "Sentinel", "Splunk SPL").
# Both axes are useful: the analyst asking "Linux use cases" wants the second
# axis. Inferred from the query bodies + the UC's source tag because the
# same `tstats` shape can target either Windows or Linux endpoint data.

# Ordered list — first match wins (specific before generic). Each entry is
# (compiled-regex, target-tag). Pattern matched against the union of all
# query strings on the UC.
import re as _re_targets

_TARGET_RULES: list[tuple] = [
    # ---- AWS ----
    # Match Splunk (source=cloudtrail) and Datadog (source:cloudtrail) and Sentinel (AWSCloudTrail).
    (_re_targets.compile(r"\b(?:source[:=]cloudtrail|sourcetype[:=]aws:cloudtrail|aws\.cloudtrail|AWSCloudTrail|AWS:CloudTrail|userIdentity\.|requestParameters\.|responseElements\.|@aws\.|IAMUser|AssumeRole|ConsoleLogin)\b", _re_targets.IGNORECASE), "aws"),
    (_re_targets.compile(r"\b(?:GuardDuty|CloudWatch|SecurityHub|EventBridge|S3Bucket|aws_s3|aws_ec2|aws_lambda|aws_kms|aws_iam|aws_eks|aws_ecs|aws_rds)\b"), "aws"),

    # ---- Azure ----
    (_re_targets.compile(r"\b(?:source:azure\.|azure\.activeDirectory|azure\.activity_logs|operationName\.value|azure\.applicationGateway|tenantId)\b", _re_targets.IGNORECASE), "azure"),
    (_re_targets.compile(r"\b(?:SigninLogs|AuditLogs|AzureActivity|AzureDiagnostics|OfficeActivity)\b"), "azure"),

    # ---- GCP ----
    (_re_targets.compile(r"\b(?:source:gcp\.|protoPayload\.methodName|protoPayload\.serviceName|google\.iam\.admin|google\.cloud)\b", _re_targets.IGNORECASE), "gcp"),

    # ---- Kubernetes ----
    (_re_targets.compile(r"\b(?:source:kubernetes\.audit|objectRef\.resource|requestObject\.spec|kubectl\b|k8s\b|RoleBinding|ClusterRole)\b", _re_targets.IGNORECASE), "kubernetes"),

    # ---- Microsoft 365 / Office 365 ----
    (_re_targets.compile(r"\b(?:source:m365|microsoft365|office365|EmailEvents|EmailUrlInfo|EmailAttachmentInfo|sharepoint|exchangeonline|teams\.microsoft|OfficeActivity)\b", _re_targets.IGNORECASE), "m365"),

    # ---- Okta ----
    (_re_targets.compile(r"\b(?:source:okta|okta\.system|@actor\.alternateId|@authenticationContext\.authenticationProvider)\b", _re_targets.IGNORECASE), "okta"),

    # ---- VCS (GitHub / GitLab / Bitbucket) ----
    (_re_targets.compile(r"\b(?:source:(?:github|gitlab|bitbucket)|github\.com/|repo\.transfer|branch_protection|personal_access_token)\b", _re_targets.IGNORECASE), "vcs"),

    # ---- macOS ----
    # Path-based patterns intentionally don't use \b on the leading slash
    # because \b is a word-boundary and '/' is not a word character.
    (_re_targets.compile(r"(?:\bosascript\b|/Applications/|\bTerminal\.app\b|\blaunchd\b|\blaunchctl\b|\.plist\b|/Library/LaunchAgents|/Library/LaunchDaemons|\bcom\.apple\.)"), "macos"),
    (_re_targets.compile(r"\b(?:macOS|MacOS|Mach-O|sip_disabled|csrutil)\b"), "macos"),

    # ---- Linux ----
    (_re_targets.compile(r"\b(?:source:linux\.|linux\.auditd|auditd\.type:(?:EXECVE|PATH|USER_AUTH)|systemctl|EXECVE|setuid|getuid)\b", _re_targets.IGNORECASE), "linux"),
    (_re_targets.compile(r"(?:/etc/cron|/etc/passwd|/var/log/|/usr/lib/|/usr/bin/|/proc/|/bin/(?:bash|sh|zsh|ksh|dash))"), "linux"),
    # Sigma-style YAML logsource declarations (no leading 'source:' prefix)
    (_re_targets.compile(r"\bproduct:\s*linux\b", _re_targets.IGNORECASE), "linux"),
    (_re_targets.compile(r"\bservice:\s*(?:auditd|syslog|cron|sshd|sudo|systemd)\b", _re_targets.IGNORECASE), "linux"),
    (_re_targets.compile(r"\b(?:bash|zsh|ksh|dash)\b\s*-c"), "linux"),

    # ---- Identity / SaaS auth ----
    (_re_targets.compile(r"\b(?:IdentityLogonEvents|IdentityDirectoryEvents|user\.session\.start|policy\.evaluate_sign_on|@usr\.|@actor\.alternateId)\b"), "identity"),

    # ---- Web application / WAF ----
    (_re_targets.compile(r"\b(?:source:waf_logs|source:application_logs|source:application-threats|@http\.url_details|@rule\.tags|sqli|xss|ssrf|rce_attempt|api_findings)\b", _re_targets.IGNORECASE), "web-app"),

    # ---- Windows (last; broad endpoint signals) ----
    (_re_targets.compile(r"\b(?:DeviceProcessEvents|DeviceFileEvents|DeviceNetworkEvents|DeviceRegistryEvents|DeviceImageLoadEvents|DeviceLogonEvents|DeviceEvents)\b"), "windows"),
    (_re_targets.compile(r"\b(?:source:windows\.(?:security|sysmon|defender|powershell|system|application))\b", _re_targets.IGNORECASE), "windows"),
    (_re_targets.compile(r"\b(?:SecurityEvent|Sysmon|HKLM|HKCU|powershell\.exe|cmd\.exe|wmic\.exe|rundll32\.exe|Win32_)\b"), "windows"),
    (_re_targets.compile(r"\b(?:EventID|EventCode)[:=]?\s*(?:4624|4625|4634|4648|4672|4688|4697|4720|4732|4768|4769|4776|7045|5140|5145|13|11|10|3)\b", _re_targets.IGNORECASE), "windows"),
    (_re_targets.compile(r"\bsourcetype\s*=\s*(?:WinEventLog|XmlWinEventLog|MSAD|Powershell|Sysmon)\b", _re_targets.IGNORECASE), "windows"),
    (_re_targets.compile(r"\\\\(?:HKLM|HKCU|Software\\Microsoft|Windows\\System32)"), "windows"),
    # Sigma logsource declarations
    (_re_targets.compile(r"\bproduct:\s*windows\b", _re_targets.IGNORECASE), "windows"),
    (_re_targets.compile(r"\bservice:\s*(?:security|sysmon|powershell|system|application|process_creation|file_event|registry_event|network_connection)\b", _re_targets.IGNORECASE), "windows"),
]


def _infer_uc_targets(uc) -> list[str]:
    """Infer target-surface tags (windows/linux/aws/etc) for a UC.

    Accepts either a UseCase object or a dict with the platform query
    fields. Returns a sorted list of unique tags. Empty list when nothing
    matches — the analyst sees "Unclassified" in the filter UI."""
    bodies: list[str] = []
    if hasattr(uc, "defender_kql"):
        for k in ("defender_kql", "sentinel_kql", "sigma_yaml", "splunk_spl", "datadog_query"):
            v = getattr(uc, k, "") or ""
            if v:
                bodies.append(v)
    elif isinstance(uc, dict):
        for k in ("defender_kql", "sentinel_kql", "kql", "sigma_yaml", "splunk_spl", "datadog_query", "search"):
            v = uc.get(k) or ""
            if v:
                bodies.append(v)
    if not bodies:
        return []
    blob = "\n".join(bodies)
    found: set[str] = set()
    for pat, tag in _TARGET_RULES:
        if pat.search(blob):
            found.add(tag)
    return sorted(found)


# Display metadata for the target tags. Order matters — used to render the
# filter pill row and the per-target landing-page list. Each entry:
#   (tag, label, icon, blurb-for-landing-page)
TARGET_DISPLAY: list[tuple] = [
    ("windows",    "Windows",     "🪟", "Detections targeting Windows endpoints — Sysmon / Security event log / Defender DeviceProcessEvents."),
    ("linux",      "Linux",       "🐧", "Detections targeting Linux servers and workstations — auditd / Sysmon for Linux / syslog."),
    ("macos",      "macOS",       "",  "Detections targeting macOS endpoints — osascript / launchd / .plist persistence / Mach-O execution."),
    ("aws",        "AWS",         "☁️", "Detections targeting AWS infrastructure — CloudTrail, IAM, S3, EC2, Lambda, KMS, GuardDuty."),
    ("azure",      "Azure",       "⛅", "Detections targeting Microsoft Azure — Activity Logs, Azure AD, Sentinel SecurityEvent / SigninLogs."),
    ("gcp",        "GCP",         "☁",  "Detections targeting Google Cloud Platform — Cloud Audit Logs, IAM, Compute, GKE."),
    ("kubernetes", "Kubernetes",  "⎈", "Detections targeting Kubernetes clusters — audit logs, pod creation, RBAC, container escapes."),
    ("m365",       "Microsoft 365","📧","Detections targeting Microsoft 365 — Exchange / SharePoint / Teams / OfficeActivity."),
    ("okta",       "Okta",        "🔑", "Detections targeting Okta IDP — system log, MFA factor changes, admin grants."),
    ("vcs",        "Source control","🐙","Detections targeting GitHub / GitLab / Bitbucket — repo transfers, PAT abuse, branch protections."),
    ("identity",   "Identity",    "👤", "Identity-platform-agnostic detections — sign-in anomalies, MFA, impossible travel."),
    ("web-app",    "Web App",     "🌐", "Application-layer detections — WAF telemetry, SQLi/XSS/SSRF/RCE, API findings."),
]


def build_matrix_data(articles_meta):
    """
    Build the compact data structure embedded into the matrix view.

    articles_meta is a list of {id, title, sev, link, ucs:[(name, UseCase),...], techs:[(tid, name)]}.

    Output structure (everything lean — IDs/refs, not full inline objects so
    the matrix can scale to 10K+ use cases without bloating the HTML):

      tactics:    [{short, name, tids:[...]}, ...]   ordered for matrix columns
      techniques: {tid: {name, parent, subs:[...], tactics:[...]}}
      ucs:        [{i:int, n:str, t:str, conf:str, ph:str, techs:[tid,...]}]
      arts:       [{i:int, id:str, title:str, sev:str, techs:[tid,...]}]
      tech_ucs:   {tid: [uc_index, ...]}
      tech_arts:  {tid: [art_index, ...]}
    """
    reg = _load_attack_data()
    if not reg:
        return None
    techs = reg.get("attack_techniques", {})
    if not techs:
        return None

    # 1. Walk every technique, build hierarchy + tactic membership
    by_tactic = {t: [] for t in TACTIC_ORDER}
    # Phase-name aliasing — the upstream STIX bundle ships some techniques
    # tagged with non-canonical phase names (`stealth` for Defense Evasion,
    # `defense-impairment` for the Impair-Defenses sub-tactic, etc.).
    # Map these onto the canonical MITRE tactic short-names so the matrix
    # column for Defense Evasion is actually populated.
    PHASE_ALIASES = {
        "stealth": "defense-evasion",
        "defense-impairment": "defense-evasion",
    }
    def _canonicalise_phases(phases):
        out = []
        for p in phases:
            if p in by_tactic:
                out.append(p); continue
            mapped = PHASE_ALIASES.get(p)
            if mapped and mapped in by_tactic:
                out.append(mapped)
        # de-dupe while preserving order
        seen = set(); deduped = []
        for p in out:
            if p in seen: continue
            seen.add(p); deduped.append(p)
        return deduped
    technique_view = {}
    for tid, info in techs.items():
        if info.get("deprecated"):
            continue
        parent = tid.rsplit(".", 1)[0] if "." in tid else None
        is_sub = parent is not None
        tactics_for = _canonicalise_phases(info.get("kill_chain_phases") or [])
        technique_view[tid] = {
            "name": info.get("name", tid),
            "parent": parent,
            "subs": [],
            "tactics": tactics_for,
            "is_sub": is_sub,
        }
        if not is_sub:
            for tac in tactics_for:
                by_tactic[tac].append(tid)
    # Wire sub-techniques to their parents
    for tid, view in technique_view.items():
        if view["parent"] and view["parent"] in technique_view:
            technique_view[view["parent"]]["subs"].append(tid)

    # Sort techniques alphabetically per tactic (mirrors attack.mitre.org)
    for tac in by_tactic:
        by_tactic[tac].sort(key=lambda t: technique_view[t]["name"].lower())
    for tid, view in technique_view.items():
        view["subs"].sort(key=lambda t: technique_view[t]["name"].lower())

    # 2. Enumerate the entire UseCase catalog defined in this module —
    #    not just the ones today's articles triggered. The matrix is the
    #    canonical use-case-to-technique mapping; today's articles add
    #    article references to whatever use cases happened to fire.
    import sys as _sys
    this_module = _sys.modules[__name__]
    all_use_cases = []
    for name in dir(this_module):
        obj = getattr(this_module, name, None)
        if isinstance(obj, UseCase):
            all_use_cases.append((name, obj))
    all_use_cases.sort(key=lambda x: x[0])

    uc_records = []
    art_records = []
    tech_ucs = {}     # tid -> [uc_idx]
    tech_arts = {}    # tid -> [art_idx]
    seen_uc_ids = {}

    for name, uc in all_use_cases:
        idx = len(uc_records)
        seen_uc_ids[name] = idx
        uc_techs = [t for t, _ in uc.techniques]
        # Platform coverage — `pl` is a 5-char string flagging which
        # platform queries this UC ships. Position 0=Defender (d/-),
        # 1=Sentinel (s/-), 2=Sigma (g/-), 3=Splunk (p/-),
        # 4=Datadog (D/-). Front-end uses it for badges on the matrix
        # and for the platform-only filters in the Detection Library.
        pl = "".join([
            "d" if uc.defender_kql else "-",
            "s" if uc.sentinel_kql else "-",
            "g" if getattr(uc, "sigma_yaml", "") else "-",
            "p" if uc.splunk_spl else "-",
            "D" if getattr(uc, "datadog_query", "") else "-",
        ])
        uc_records.append({
            "i": idx,
            "n": name,
            "t": uc.title,
            "conf": uc.confidence,
            "ph": uc.kill_chain,
            "src": "internal",
            "tier": getattr(uc, "tier", "hunting"),
            "pl": pl,                    # platform coverage d/s/g/p/D
            "tg": _infer_uc_targets(uc), # target surfaces (windows/linux/aws/...)
            "techs": uc_techs,
            "arts": [],  # populated when articles cite this UC below
        })
        for tid in uc_techs:
            if tid in technique_view:
                tech_ucs.setdefault(tid, []).append(idx)

    # 2b. Pull synced ESCU detections (Splunk Security Content) into the matrix.
    #     Each is a use case mapped to MITRE techniques. This brings the matrix
    #     from ~24 hand-built UCs to thousands of reference detections.
    escu_list = reg.get("escu_detections") or []
    escu_added = 0
    for det in escu_list:
        tech_ids = []
        for t in (det.get("techniques") or []):
            tid = t.get("id") if isinstance(t, dict) else t
            if tid and tid in technique_view:
                tech_ids.append(tid)
        if not tech_ids:
            continue
        idx = len(uc_records)
        det_id = det.get("id") or f"escu_{idx}"
        # First kill_chain_phase if available (Splunk uses MITRE phase names)
        phases = det.get("kill_chain_phases") or []
        ph = phases[0] if phases else ""
        # Map MITRE phase short-names to our 7-stage kill-chain buckets
        ph_map = {
            "reconnaissance":"recon", "resource-development":"recon",
            "initial-access":"delivery", "execution":"exploit",
            "persistence":"install", "privilege-escalation":"install",
            "defense-evasion":"install", "credential-access":"actions",
            "discovery":"actions", "lateral-movement":"actions",
            "collection":"actions", "exfiltration":"actions",
            "command-and-control":"c2", "impact":"actions",
        }
        ph_short = ph_map.get(ph.lower() if ph else "", "actions")
        # ESCU detection types map to tiers as follows:
        #   TTP / Correlation       -> alerting (specific behaviour, deployable)
        #   Anomaly / Hunting       -> hunting  (needs tuning per environment)
        det_type = (det.get("type") or "").lower()
        if det_type in ("ttp", "correlation"):
            tier = "alerting"
        else:
            tier = "hunting"
        # Run target inference on the ESCU search body so e.g. cloudtrail
        # ESCU detections light up the AWS pill instead of staying generic.
        escu_tg = _infer_uc_targets({"splunk_spl": det.get("search") or ""})
        uc_records.append({
            "i": idx,
            "n": det_id[:36],
            "t": det.get("name", det_id)[:140],
            "conf": det.get("type", "Detection"),
            "ph": ph_short,
            "src": "escu",
            "tier": tier,
            "pl": "---p-",               # ESCU = Splunk SPL-only (5 positions)
            "tg": escu_tg,
            "techs": tech_ids,
            "arts": [],
        })
        for tid in tech_ids:
            tech_ucs.setdefault(tid, []).append(idx)
        escu_added += 1
    if escu_added:
        print(f"[*] Matrix: added {escu_added} ESCU detections from registry")

    # Walk current articles, register article->technique and article->UC links.
    # If a UC is bespoke (LLM-generated from this article — not a module-level
    # internal UC and not an ESCU detection), register it as a new matrix entry
    # so it shows up in the Detection Library + matrix views with its proper
    # per-platform coverage flags. Without this, the Library only lists the 25
    # hand-built internal UCs and ignores the hundreds of article-bespoke ones.
    for a in articles_meta:
        a_idx = len(art_records)
        art_techs = sorted({t for t, _ in a["techs"]})
        art_records.append({
            "i": a_idx,
            "id": a["id"],
            "title": a["title"][:140],
            "sev": a["sev"],
            "techs": art_techs,
        })
        for tid in art_techs:
            if tid in technique_view:
                tech_arts.setdefault(tid, []).append(a_idx)
        for uc_var, uc in a["ucs"]:
            if uc_var in seen_uc_ids:
                uc_records[seen_uc_ids[uc_var]]["arts"].append(a_idx)
                continue
            # Bespoke UC — fresh entry with the same shape as internal UCs.
            idx = len(uc_records)
            seen_uc_ids[uc_var] = idx
            uc_techs = [t for t, _ in uc.techniques]
            pl = "".join([
                "d" if uc.defender_kql else "-",
                "s" if uc.sentinel_kql else "-",
                "g" if getattr(uc, "sigma_yaml", "") else "-",
                "p" if uc.splunk_spl else "-",
                "D" if getattr(uc, "datadog_query", "") else "-",
            ])
            uc_records.append({
                "i": idx,
                "n": uc_var,
                "t": uc.title,
                "conf": uc.confidence,
                "ph": uc.kill_chain,
                "src": "bespoke",
                "tier": getattr(uc, "tier", "hunting"),
                "pl": pl,
                "tg": _infer_uc_targets(uc),
                "techs": uc_techs,
                "arts": [a_idx],
            })
            for tid in uc_techs:
                if tid in technique_view:
                    tech_ucs.setdefault(tid, []).append(idx)

    # 3. Compose tactics array in canonical order
    tactics_out = []
    for short in TACTIC_ORDER:
        tactics_out.append({
            "short": short,
            "name": TACTIC_DISPLAY[short],
            "tids": by_tactic.get(short, []),
        })

    return {
        "tactics": tactics_out,
        "techniques": technique_view,
        "ucs": uc_records,
        "arts": art_records,
        "tech_ucs": tech_ucs,
        "tech_arts": tech_arts,
        "stats": {
            "total_techs": sum(1 for t, v in technique_view.items() if not v["is_sub"]),
            "total_subs": sum(1 for t, v in technique_view.items() if v["is_sub"]),
            "covered_techs": len(set(tech_ucs.keys()) | set(tech_arts.keys())),
            "ucs": len(uc_records),
            "arts": len(art_records),
        },
    }


# =============================================================================
# IOC aggregation + threat intel exports (CSV / JSON / STIX 2.1 / Splunk lookup)
# =============================================================================

import csv as _csv
import uuid as _uuid

INTEL_DIR = Path(__file__).parent / "intel"
CATALOG_DIR = Path(__file__).parent / "catalog"

_SEV_RANK = {"crit": 4, "high": 3, "med": 2, "low": 1}


def aggregate_iocs(articles_meta):
    """Dedupe IOCs across articles, attaching source attribution + context.

    Every IOC included here has passed the high-fidelity bar in
    `extract_indicators()`:
      - CVE & hash IOCs: regex-extracted (unambiguous format)
      - Domain/IP IOCs:  only present if the source author defanged them
                         (`evil[.]com`, `1[.]2[.]3[.]4`, `hxxps://...`)
    The `confidence` field below tells consumers which path each IOC took.
    """
    iocs = {}  # (type, value_lower) -> dict
    type_buckets = [
        ("cve", "cves", "regex"),
        ("ipv4", "ips", "defanged"),
        ("domain", "domains", "defanged"),
        ("sha256", "sha256", "regex"),
        ("sha1", "sha1", "regex"),
        ("md5", "md5", "regex"),
    ]
    for a in articles_meta:
        ind = a.get("ind") or {}
        sev = a.get("sev", "low")
        sources = a.get("sources") or []
        article_ref = {
            "id": a["id"],
            "title": a["title"],
            "link": a["link"],
            "published": a.get("published", ""),
            "sev": sev,
        }
        for ioc_type, ind_key, source_path in type_buckets:
            for value in ind.get(ind_key, []) or []:
                key = (ioc_type, str(value).lower())
                ent = iocs.get(key)
                if ent is None:
                    iocs[key] = {
                        "value": value,
                        "type": ioc_type,
                        "confidence": "high",  # everything that survives extraction is high-confidence by design
                        "extraction": source_path,  # "regex" or "defanged" — provenance of the extraction
                        "severity": sev,
                        "sources": list(sources),
                        "articles": [article_ref],
                        "first_seen": article_ref["published"] or "",
                    }
                else:
                    if article_ref not in ent["articles"]:
                        ent["articles"].append(article_ref)
                    for s in sources:
                        if s not in ent["sources"]:
                            ent["sources"].append(s)
                    if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(ent["severity"], 0):
                        ent["severity"] = sev
    out = list(iocs.values())
    out.sort(key=lambda x: (-_SEV_RANK.get(x["severity"], 0), x["type"], x["value"].lower()))
    # Enrich each IOC with public-feed cross-references (ThreatFox / URLhaus).
    # Free, no API key, rate-limited but generous. Toggle off with
    # USECASEINTEL_ENRICH=0 if running offline.
    if os.environ.get("USECASEINTEL_ENRICH", "1") not in ("0", "false", "no", ""):
        _enrich_iocs(out)
    return out


# ----- IOC enrichment via free public threat-intel APIs ----------------
# ThreatFox (abuse.ch) — JSON API, free, no key. Returns malware family +
# first-seen + reporter for any IOC type. URLhaus is a sibling for URLs.
# We keep the call rate gentle (<= 1 req per 0.4s) and cache results to
# disk so re-runs reuse prior enrichment.
ENRICH_CACHE_DIR = Path(__file__).parent / "intel" / ".enrich_cache"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API   = "https://urlhaus-api.abuse.ch/v1/"


def _enrich_one(value, ioc_type, cache_dir, auth_key):
    """Look up a single IOC in ThreatFox + URLhaus. Returns dict or {}.

    abuse.ch APIs (ThreatFox + URLhaus) require an Auth-Key header as of
    2024-2025. If no key is supplied we never even call them — the
    enrichment columns just stay blank. Free auth keys are available at
    https://auth.abuse.ch/ — register and set ABUSECH_API_KEY."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(value))[:60]
    cache_path = cache_dir / f"{ioc_type}_{safe}.json"
    if cache_path.exists():
        try:
            return __import__("json").loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    if not auth_key:
        return {}
    out = {}
    headers = {
        "User-Agent": FETCH_USER_AGENT,
        "Auth-Key": auth_key,
    }
    try:
        import requests as _req
        time.sleep(0.4)
        tf_query_type = {
            "cve":"cve","ipv4":"ip","domain":"domain","md5":"md5",
            "sha1":"sha1","sha256":"sha256","url":"url",
        }.get(ioc_type)
        if tf_query_type:
            r = _req.post(THREATFOX_API,
                          json={"query": "search_ioc", "search_term": value},
                          headers=headers, timeout=15)
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    items = d.get("data") or []
                    if items:
                        first = items[0]
                        out["threatfox_malware"] = first.get("malware_printable") or first.get("malware") or ""
                        out["threatfox_threat_type"] = first.get("threat_type") or ""
                        out["threatfox_first_seen"] = first.get("first_seen") or ""
                        out["threatfox_reporter"] = first.get("reporter") or ""
                        out["threatfox_url"] = f"https://threatfox.abuse.ch/ioc/{first.get('id','')}"
                        out["threatfox_hits"] = len(items)
            elif r.status_code == 401:
                out["enrich_error"] = "ThreatFox: 401 unauthorized (set ABUSECH_API_KEY)"
        if ioc_type in ("domain","ipv4"):
            time.sleep(0.4)
            r = _req.post(URLHAUS_API + "host/",
                          data={"host": value},
                          headers=headers, timeout=15)
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    out["urlhaus_url_count"] = d.get("url_count") or 0
                    out["urlhaus_first_seen"] = d.get("firstseen") or ""
                    out["urlhaus_blacklists"] = ", ".join((d.get("blacklists") or {}).keys())
                    out["urlhaus_url"] = d.get("urlhaus_reference") or ""
            elif r.status_code == 401:
                out["enrich_error"] = "URLhaus: 401 unauthorized (set ABUSECH_API_KEY)"
    except Exception as e:
        out["enrich_error"] = str(e)[:80]
    try:
        cache_path.write_text(__import__("json").dumps(out), encoding="utf-8")
    except Exception:
        pass
    return out


def _enrich_iocs(iocs):
    """Annotate each IOC dict with ThreatFox / URLhaus enrichment in-place."""
    auth_key = os.environ.get("ABUSECH_API_KEY", "").strip()
    if not auth_key:
        # Don't even try — abuse.ch APIs require auth as of 2024-2025.
        # Log once so the user knows enrichment is disabled, then bail.
        print("[*] IOC enrichment skipped: set ABUSECH_API_KEY (free at https://auth.abuse.ch/) to enable ThreatFox/URLhaus cross-reference")
        return
    enriched = 0; auth_err = 0
    for i in iocs:
        meta = _enrich_one(i["value"], i["type"], ENRICH_CACHE_DIR, auth_key)
        if meta:
            i["enrichment"] = meta
            if meta.get("threatfox_malware") or meta.get("urlhaus_url_count"):
                enriched += 1
            elif "401" in (meta.get("enrich_error") or ""):
                auth_err += 1
    if auth_err:
        print(f"[!] IOC enrichment: {auth_err} 401-unauth responses — verify ABUSECH_API_KEY is correct")
    print(f"[*] IOC enrichment: {enriched} IOCs cross-referenced via ThreatFox/URLhaus")


def _iocs_to_csv_rows(iocs):
    rows = [[
        "value", "type", "severity", "sources", "first_seen",
        "article_titles", "article_links", "source_count", "article_count",
        "threatfox_malware", "threatfox_threat_type", "urlhaus_url_count",
        "urlhaus_blacklists", "enrichment_url"
    ]]
    for i in iocs:
        e = i.get("enrichment") or {}
        rows.append([
            i["value"], i["type"], i["severity"],
            "; ".join(i["sources"]),
            i.get("first_seen", ""),
            "; ".join(a["title"] for a in i["articles"]),
            "; ".join(a["link"] for a in i["articles"]),
            str(len(i["sources"])), str(len(i["articles"])),
            e.get("threatfox_malware",""),
            e.get("threatfox_threat_type",""),
            str(e.get("urlhaus_url_count","")),
            e.get("urlhaus_blacklists",""),
            e.get("threatfox_url") or e.get("urlhaus_url") or "",
        ])
    return rows


def _iocs_to_splunk_lookup_rows(iocs):
    rows = [["indicator", "indicator_type", "severity", "first_seen", "description", "source_url"]]
    for i in iocs:
        first = i["articles"][0] if i["articles"] else {"title": "", "link": ""}
        rows.append([
            i["value"], i["type"], i["severity"],
            i.get("first_seen", ""), first["title"], first["link"],
        ])
    return rows


def _stix_pattern(ioc_type, value):
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    if ioc_type == "sha1":
        return f"[file:hashes.'SHA-1' = '{value}']"
    if ioc_type == "md5":
        return f"[file:hashes.MD5 = '{value}']"
    if ioc_type == "cve":
        return f"[vulnerability:name = '{value}']"
    return f"[x-custom:value = '{value}']"


def _iocs_to_stix(iocs, generated_iso):
    bundle_id = f"bundle--{_uuid.uuid4()}"
    objects = []
    for i in iocs:
        first_link = i["articles"][0]["link"] if i["articles"] else ""
        first_title = i["articles"][0]["title"] if i["articles"] else ""
        ioc_id = f"indicator--{_uuid.uuid4()}"
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ioc_id,
            "created": generated_iso,
            "modified": generated_iso,
            "name": f"{i['type'].upper()}: {i['value']}",
            "pattern": _stix_pattern(i["type"], i["value"]),
            "pattern_type": "stix",
            "valid_from": generated_iso,
            "labels": ["malicious-activity"],
            "external_references": (
                [{"source_name": s["title"][:60], "url": s["link"]} for s in i["articles"][:3]]
            ),
            "x_severity": i["severity"],
            "x_sources": i["sources"],
        }
        objects.append(obj)
    return {"type": "bundle", "id": bundle_id, "objects": objects}


def _xml_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                  .replace('"', "&quot;").replace("'", "&apos;"))


def _iocs_to_rss(iocs, generated_iso, repo_url="https://github.com/Virtualhaggis/usecaseintel"):
    """RSS 2.0 feed of IOCs — newest-first, last 100 items."""
    sorted_iocs = sorted(
        iocs,
        key=lambda x: (x.get("first_seen") or "", x.get("type"), x.get("value", "").lower()),
        reverse=True,
    )[:100]

    def to_rfc2822(iso_date):
        try:
            d = dt.datetime.fromisoformat(iso_date + "T00:00:00+00:00") if len(iso_date) == 10 \
                else dt.datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
            return d.strftime("%a, %d %b %Y %H:%M:%S +0000")
        except Exception:
            return ""

    items_xml = []
    for ioc in sorted_iocs:
        first_art = (ioc.get("articles") or [{}])[0]
        link = first_art.get("link") or repo_url
        title = f"[{ioc['type'].upper()}/{ioc['severity'].upper()}] {ioc['value']}"
        desc_html = (
            f"<p><strong>{_xml_escape(ioc['type'].upper())}:</strong> "
            f"<code>{_xml_escape(ioc['value'])}</code></p>"
            f"<p>Severity: <strong>{_xml_escape(ioc['severity'])}</strong> · "
            f"First seen: {_xml_escape(ioc.get('first_seen',''))} · "
            f"Sources: {_xml_escape(', '.join(ioc.get('sources', [])) or '—')}</p>"
            f"<p>Context: {_xml_escape(first_art.get('title',''))}</p>"
        )
        guid = f"usecaseintel:{ioc['type']}:{ioc['value']}"
        cats = "".join(
            f"\n      <category>{_xml_escape(s)}</category>"
            for s in ioc.get("sources", [])
        )
        items_xml.append(
            "    <item>\n"
            f"      <title>{_xml_escape(title)}</title>\n"
            f"      <link>{_xml_escape(link)}</link>\n"
            f"      <description>{_xml_escape(desc_html)}</description>\n"
            f"      <guid isPermaLink=\"false\">{_xml_escape(guid)}</guid>\n"
            f"      <pubDate>{to_rfc2822(ioc.get('first_seen',''))}</pubDate>"
            f"{cats}\n"
            "    </item>"
        )

    chan_pub = ""
    try:
        chan_pub = dt.datetime.fromisoformat(
            generated_iso.replace("Z", "+00:00")
        ).strftime("%a, %d %b %Y %H:%M:%S +0000")
    except Exception:
        pass
    self_url = f"https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.rss.xml"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
        '  <channel>\n'
        '    <title>Use Case Intel — Threat Intel Feed</title>\n'
        '    <description>High-fidelity IOCs aggregated from The Hacker News, BleepingComputer, '
        'Microsoft Security Blog and CISA KEV. Refreshed daily. CVEs/hashes via regex; '
        'domains/IPs only when defanged by the source author.</description>\n'
        f'    <link>{repo_url}</link>\n'
        f'    <atom:link href="{self_url}" rel="self" type="application/rss+xml" />\n'
        '    <language>en-us</language>\n'
        f'    <pubDate>{chan_pub}</pubDate>\n'
        f'    <lastBuildDate>{chan_pub}</lastBuildDate>\n'
        '    <generator>usecaseintel/generate.py</generator>\n'
        + "\n".join(items_xml) +
        '\n  </channel>\n'
        '</rss>\n'
    )


def write_intel_files(iocs, generated_iso):
    INTEL_DIR.mkdir(exist_ok=True)
    # CSV
    with (INTEL_DIR / "iocs.csv").open("w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        for row in _iocs_to_csv_rows(iocs):
            w.writerow(row)
    # JSON
    payload = {"generated": generated_iso, "count": len(iocs), "iocs": iocs}
    (INTEL_DIR / "iocs.json").write_text(
        __import__("json").dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )
    # STIX 2.1 bundle
    (INTEL_DIR / "iocs.stix.json").write_text(
        __import__("json").dumps(_iocs_to_stix(iocs, generated_iso), indent=2),
        encoding="utf-8",
    )
    # Splunk lookup CSV
    with (INTEL_DIR / "splunk_lookup_iocs.csv").open("w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        for row in _iocs_to_splunk_lookup_rows(iocs):
            w.writerow(row)
    # RSS 2.0
    (INTEL_DIR / "iocs.rss.xml").write_text(
        _iocs_to_rss(iocs, generated_iso),
        encoding="utf-8",
    )


def write_catalog_files(generated_iso):
    """Emit catalog/ JSON exports of the use-case catalog for programmatic consumers."""
    CATALOG_DIR.mkdir(exist_ok=True)
    json_lib = __import__("json")
    ucs_array = []
    coverage = {}
    if _LOADED_UCS:
        for uc_id, uc in sorted(_LOADED_UCS.items()):
            ucs_array.append({
                "id": uc_id,
                "title": uc.title,
                "kill_chain": uc.kill_chain,
                "confidence": uc.confidence,
                "description": uc.description,
                "implementations": [
                    p for p, q in (("splunk", uc.splunk_spl), ("defender", uc.defender_kql)) if q
                ],
                "mitre_attack": [{"id": t, "name": n} for t, n in uc.techniques],
                "data_models": uc.data_models,
                "splunk_spl": uc.splunk_spl or None,
                "defender_kql": uc.defender_kql or None,
            })
            for tid, _ in uc.techniques:
                coverage.setdefault(tid, []).append(uc_id)
    (CATALOG_DIR / "use_cases.json").write_text(
        json_lib.dumps({"generated": generated_iso, "count": len(ucs_array), "use_cases": ucs_array},
                       indent=2),
        encoding="utf-8",
    )
    rules_array = []
    if _LOADED_RULES:
        for r in _LOADED_RULES:
            rules_array.append({
                "name": r.name,
                "triggers": list(r.triggers),
                "fires": [k for k, v in (_LOADED_UCS or {}).items() if v in r.use_cases],
            })
    (CATALOG_DIR / "rules.json").write_text(
        json_lib.dumps({"generated": generated_iso, "count": len(rules_array), "rules": rules_array},
                       indent=2),
        encoding="utf-8",
    )
    (CATALOG_DIR / "attack_coverage.json").write_text(
        json_lib.dumps({"generated": generated_iso,
                        "tactics_count": len({uc.kill_chain for uc in (_LOADED_UCS or {}).values()}),
                        "technique_to_use_cases": coverage},
                       indent=2),
        encoding="utf-8",
    )
    # Full per-UC detail sidecar (loaded by index.html via <script src=...>).
    # This is the body of every detection — internal SPL+KQL plus the synced
    # Splunk ESCU search bodies. Kept out of the main HTML so the page weight
    # stays manageable and the browser can cache the heavy payload separately.
    full = {}
    # Internal UCs (full SPL + KQL from YAML)
    if _LOADED_UCS:
        for uc_id, uc in _LOADED_UCS.items():
            full[uc_id] = {
                "name": uc.title,
                "description": uc.description,
                "kill_chain": uc.kill_chain,
                "confidence": uc.confidence,
                "tier": getattr(uc, "tier", "hunting"),
                "fp_rate_estimate": getattr(uc, "fp_rate_estimate", "unknown"),
                "required_telemetry": list(getattr(uc, "required_telemetry", []) or []),
                "techniques": [{"id": t, "name": n} for t, n in uc.techniques],
                "data_models": list(uc.data_models or []),
                "splunk_spl": uc.splunk_spl or "",
                "defender_kql": uc.defender_kql or "",
                "source": "internal",
                "source_url": f"https://github.com/Virtualhaggis/usecaseintel/blob/main/use_cases/{uc.kill_chain}/{uc_id}.yml",
            }
    # ESCU detections (Splunk Security Content)
    try:
        reg = json_lib.loads(REGISTRY_PATH_FOR_MATRIX.read_text(encoding="utf-8"))
        for det in (reg.get("escu_detections") or []):
            det_id = det.get("id") or ""
            if not det_id: continue
            # Trim id used as JS key to first 36 chars to match matrix builder
            key = det_id[:36]
            det_type_lower = (det.get("type") or "").lower()
            tier = "alerting" if det_type_lower in ("ttp", "correlation") else "hunting"
            full[key] = {
                "name": det.get("name", ""),
                "description": det.get("description", ""),
                "kill_chain": (det.get("kill_chain_phases") or [""])[0],
                "confidence": det.get("type", "Detection"),
                "tier": tier,
                "techniques": det.get("techniques") or [],
                "data_models": det.get("data_models") or [],
                "splunk_spl": det.get("search", ""),
                "defender_kql": "",
                "source": "splunk_escu",
                "source_url": f"https://github.com/splunk/security_content/search?q={det_id}",
            }
    except Exception as _e:
        print(f"[!] Failed to embed ESCU details: {_e}")
    # Emit as JS so a plain <script src=...> include works for file:// + http
    js_payload = json_lib.dumps(full, separators=(",", ":"))
    (CATALOG_DIR / "use_cases_full.js").write_text(
        "/* auto-generated; do not edit by hand */\n"
        "window.__UC_DETAILS__ = " + js_payload + ";\n",
        encoding="utf-8",
    )
    # Also emit JSON for non-browser consumers
    (CATALOG_DIR / "use_cases_full.json").write_text(
        json_lib.dumps({"generated": generated_iso, "count": len(full),
                        "details": full}, separators=(",", ":")),
        encoding="utf-8",
    )
    print(f"[*] Use case detail sidecar: {len(full)} entries  ->  catalog/use_cases_full.js")
    # Per-platform rule packs (SIEM-native exports)
    _write_rule_packs(generated_iso)


def _write_rule_packs(generated_iso):
    """Emit per-platform rule packs for direct SIEM consumption.

    Outputs go to rule_packs/:
      - splunk/savedsearches.conf       — drop-in for Splunk app
      - sentinel/<uc>.json              — Sentinel analytics rule (ARM template)
      - elastic/<uc>.json               — Elastic detection rule
      - sigma/<uc>.yml                  — Sigma format (multi-vendor interchange)

    Only internal UCs are exported (not the 2150 ESCU detections — those
    already exist in their native Splunk Security Content repo).
    """
    if not _LOADED_UCS:
        return
    json_lib = __import__("json")
    rp_dir = Path(__file__).parent / "rule_packs"
    rp_dir.mkdir(exist_ok=True)
    splunk_dir = rp_dir / "splunk"; splunk_dir.mkdir(exist_ok=True)
    sentinel_dir = rp_dir / "sentinel"; sentinel_dir.mkdir(exist_ok=True)
    elastic_dir = rp_dir / "elastic"; elastic_dir.mkdir(exist_ok=True)
    sigma_dir = rp_dir / "sigma"; sigma_dir.mkdir(exist_ok=True)

    splunk_lines = [
        "# Splunk savedsearches.conf — auto-generated by usecaseintel",
        f"# Generated: {generated_iso}",
        f"# {len(_LOADED_UCS)} use cases. Drop into a Splunk app's local/",
        "# folder. Each saved search is disabled by default — enable per",
        "# environment after a 7-day backfill review.",
        "",
    ]

    for uc_id, uc in sorted(_LOADED_UCS.items()):
        tier = getattr(uc, "tier", "hunting")
        cron = "0 */6 * * *" if tier == "alerting" else "0 8 * * *"  # alerting hourly-ish, hunting daily
        # ---- Splunk savedsearches.conf stanza ----
        if uc.splunk_spl:
            splunk_lines.append(f"[usecaseintel - {uc.title}]")
            splunk_lines.append(f"description = {(uc.description or '').splitlines()[0] if uc.description else ''}")
            splunk_lines.append(f"search = {uc.splunk_spl.strip().splitlines()[0] if uc.splunk_spl else ''}")  # 1-line preview
            splunk_lines.append(f"# (full multi-line search below)")
            for line in uc.splunk_spl.strip().splitlines():
                splunk_lines.append(f"#   {line}")
            # Non-accelerated variant — for SOCs without CIM data-model
            # acceleration enabled. Same logic, summariesonly=false.
            if _spl_has_dual_form(uc.splunk_spl):
                alt = _spl_make_unsummarised(uc.splunk_spl)
                splunk_lines.append(f"#")
                splunk_lines.append(f"# --- Non-summarised variant (no CIM acceleration required) ---")
                splunk_lines.append(f"# Replace the `search =` line above with the body below if your")
                splunk_lines.append(f"# environment doesn't have CIM data-model acceleration enabled.")
                for line in alt.strip().splitlines():
                    splunk_lines.append(f"#   {line}")
            splunk_lines.append(f"cron_schedule = {cron}")
            splunk_lines.append(f"dispatch.earliest_time = -24h@h")
            splunk_lines.append(f"dispatch.latest_time = now")
            splunk_lines.append(f"enableSched = 0  # ENABLE AFTER REVIEW (tier={tier})")
            splunk_lines.append(f"action.notable = {1 if tier == 'alerting' else 0}")
            splunk_lines.append(f"action.notable.param.severity = high")
            splunk_lines.append(f"action.notable.param.security_domain = endpoint")
            techs = ",".join(t for t, _ in uc.techniques)
            splunk_lines.append(f"action.correlationsearch.annotations = {{\"mitre_attack\":[{techs}]}}")
            splunk_lines.append(f"# usecaseintel.tier = {tier}")
            splunk_lines.append(f"# usecaseintel.fp_rate = {getattr(uc, 'fp_rate_estimate', 'unknown')}")
            splunk_lines.append("")

        # ---- Sentinel analytics rule (Microsoft.SecurityInsights JSON) ----
        # Prefer the Sentinel-shape KQL (uses TimeGenerated + Sentinel tables);
        # fall back to defender_kql for legacy UCs that haven't been ported yet.
        sentinel_rule_kql = uc.sentinel_kql or uc.defender_kql
        if sentinel_rule_kql:
            sentinel_rule = {
                "schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "resources": [{
                    "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                    "apiVersion": "2022-12-01-preview",
                    "name": f"[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/{uc_id}')]",
                    "kind": "Scheduled",
                    "properties": {
                        "displayName": uc.title,
                        "description": uc.description or uc.title,
                        "severity": "High" if tier == "alerting" else "Low",
                        "enabled": False,  # ALWAYS off until reviewed
                        "query": sentinel_rule_kql,
                        "queryFrequency": "PT1H" if tier == "alerting" else "PT1D",
                        "queryPeriod": "PT24H",
                        "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0,
                        "tactics": [],  # filled below
                        "techniques": [t for t, _ in uc.techniques],
                        "alertRuleTemplateName": uc_id,
                        "customDetails": {
                            "tier": tier,
                            "fp_rate_estimate": getattr(uc, "fp_rate_estimate", "unknown"),
                            "source_url": f"https://github.com/Virtualhaggis/usecaseintel/blob/main/use_cases/{uc.kill_chain}/{uc_id}.yml",
                        },
                    },
                }],
                "parameters": {
                    "workspaceName": {"type": "string"}
                }
            }
            (sentinel_dir / f"{uc_id}.json").write_text(
                json_lib.dumps(sentinel_rule, indent=2), encoding="utf-8")

        # ---- Elastic detection rule ----
        if uc.defender_kql or uc.splunk_spl:
            # Elastic accepts EQL / KQL — Defender KQL is closer in shape.
            elastic_rule = {
                "name": uc.title,
                "description": uc.description or uc.title,
                "risk_score": 73 if tier == "alerting" else 21,
                "severity": "high" if tier == "alerting" else "low",
                "type": "query",
                "language": "kuery",
                "enabled": False,  # OFF until reviewed
                "interval": "1h" if tier == "alerting" else "24h",
                "from": "now-24h",
                "index": ["logs-*", "winlogbeat-*", "endgame-*"],
                "query": "event.action:* AND _exists_:host.name",  # placeholder — analyst port-over needed
                "threat": [{
                    "framework": "MITRE ATT&CK",
                    "tactic": {"id": "", "name": uc.kill_chain, "reference": ""},
                    "technique": [{"id": t, "name": n, "reference": f"https://attack.mitre.org/techniques/{t}/"}
                                  for t, n in uc.techniques[:3]],
                }],
                "tags": ["usecaseintel", f"tier:{tier}", uc.kill_chain],
                "note": (
                    "**Auto-generated from usecaseintel — analyst port-over required.** "
                    "Original Splunk SPL / Defender KQL bodies preserved in the "
                    "`reference` URL. Translate the source query to Elastic's "
                    "ECS / EQL syntax before enabling.\n\n"
                    f"### Source query (Defender KQL)\n```\n{uc.defender_kql or '(none)'}\n```"
                ),
                "references": [
                    f"https://github.com/Virtualhaggis/usecaseintel/blob/main/use_cases/{uc.kill_chain}/{uc_id}.yml",
                ],
                "meta": {
                    "tier": tier,
                    "fp_rate_estimate": getattr(uc, "fp_rate_estimate", "unknown"),
                },
            }
            (elastic_dir / f"{uc_id}.json").write_text(
                json_lib.dumps(elastic_rule, indent=2), encoding="utf-8")

        # ---- Sigma rule (universal interchange) ----
        sigma_yaml = _emit_sigma(uc_id, uc, tier)
        if sigma_yaml:
            (sigma_dir / f"{uc_id}.yml").write_text(sigma_yaml, encoding="utf-8")

    (splunk_dir / "savedsearches.conf").write_text("\n".join(splunk_lines), encoding="utf-8")

    # README for the rule_packs/ directory
    readme = f"""# Rule packs — auto-generated SIEM-native exports

Generated: {generated_iso}

This directory contains per-platform versions of every internal use case
in the catalogue. Drop-in for the named SIEM, but **always disabled by
default** — review each rule against your environment before enabling.

| Directory | Format | Notes |
|---|---|---|
| `splunk/savedsearches.conf` | Splunk app config | Stanzas with full SPL embedded as comments. Enable per environment. |
| `sentinel/<uc>.json` | ARM template | Microsoft Sentinel analytics rule. Deploy with `az deployment group create`. |
| `elastic/<uc>.json` | Elastic detection rule | Translation TODO — KQL bodies need port to ECS/EQL. |
| `sigma/<uc>.yml` | Sigma | Universal interchange — convert with sigma-cli to your SIEM dialect. |

Tier-aware defaults:
- `alerting` UCs schedule hourly, severity High
- `hunting` UCs schedule daily, severity Low

All exports include `tier`, `fp_rate_estimate`, `mitre_attack` annotations.
"""
    (rp_dir / "README.md").write_text(readme, encoding="utf-8")
    print(f"[*] Rule packs: {len(_LOADED_UCS)} UCs  ->  rule_packs/{{splunk,sentinel,elastic,sigma}}/")


def _emit_sigma(uc_id, uc, tier):
    """Emit a Sigma rule. Sigma is multi-vendor — pretty-prints fields and
    leaves the heavy logic translation to sigma-cli on the consumer side.
    The `detection.condition` is intentionally simple — analysts run sigma-cli
    against their backend SIEM to expand the patterns we put in `keywords`."""
    techs = [t for t, _ in uc.techniques]
    # Pull a few discriminating tokens from the SPL/KQL to seed Sigma keywords.
    blob = (uc.splunk_spl or "") + " " + (uc.defender_kql or "")
    tokens = []
    for m in re.finditer(r'"([A-Za-z0-9_.\\\-\/]{3,80})"', blob):
        tokens.append(m.group(1))
    tokens = list(dict.fromkeys(tokens))[:25]
    if not tokens:
        return ""
    yaml_lines = [
        f"title: {uc.title}",
        f"id: {uc_id}",
        f"status: experimental",
        f"description: {(uc.description or uc.title).splitlines()[0]}",
        f"references:",
        f"  - https://github.com/Virtualhaggis/usecaseintel/blob/main/use_cases/{uc.kill_chain}/{uc_id}.yml",
        f"author: usecaseintel auto-generator",
        f"tags:",
        f"  - usecaseintel.tier.{tier}",
        f"  - usecaseintel.kill_chain.{uc.kill_chain}",
    ]
    for t in techs:
        yaml_lines.append(f"  - attack.{t.lower().replace('.','_')}")
    yaml_lines.extend([
        f"logsource:",
        f"  category: process_creation",
        f"  product: windows",
        f"detection:",
        f"  selection:",
        f"    Image|contains:",
    ])
    for tok in tokens[:15]:
        # Sigma quoting — escape backslashes
        esc = tok.replace("\\", "\\\\")
        yaml_lines.append(f"      - '{esc}'")
    yaml_lines.extend([
        f"  condition: selection",
    ])
    yaml_lines.extend([
        f"falsepositives:",
        f"  - Legitimate use of any of the above strings on dev / admin hosts",
        f"  - Tune via known-good allowlist before alerting",
        f"level: {'high' if tier == 'alerting' else 'low'}",
    ])
    return "\n".join(yaml_lines) + "\n"


# =============================================================================
# Per-article briefings — Markdown files committed to briefings/YYYY-MM-DD/
# =============================================================================

BRIEFINGS_DIR = Path(__file__).parent / "briefings"


def _slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:60] or "untitled"


def _art_slug(article: dict, published: str | None = None) -> str:
    """Stable share-link slug for an article: '<YYYY-MM-DD>-<title-slug>'.
    Survives future regens because it's content-derived, not position-
    derived. Empty / undated articles fall through to 'undated-<slug>'."""
    pub = published or article.get("published") or "undated"
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", pub):
        pub = "undated"
    return f"{pub}-{_slug(article.get('title', ''))}"


def _uc_slug(uc) -> str:
    """Stable share-link slug for a use case: 10 hex chars from SHA1 of
    title + Defender KQL. Stable across regens unless the UC content
    actually changes; ~10⁻¹² collision probability across our catalog."""
    import hashlib
    blob = (getattr(uc, "title", "") or "") + "|" + (getattr(uc, "defender_kql", "") or "")
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:10]


def _kev_briefing(article, ind, ucs):
    cves = ind.get("cves", []) or []
    cve = cves[0] if cves else "CVE-UNKNOWN"
    title = article["title"]
    sev = article.get("sev", "high")
    src = ", ".join(article.get("sources", []) or [article.get("source", "")])
    pub = article.get("published", "")
    body = article.get("raw_body", "")
    vendor = ""
    if "—" in title:
        rest = title.split("—", 1)[1].strip()
        vendor = rest.rsplit(" Vulnerability", 1)[0].strip() if " Vulnerability" in rest else rest

    return f"""# [{sev.upper()}] {title}

**Source:** {src}
**Published:** {pub}
**Article:** {article.get('link', '')}

## Threat Profile

CISA KEV entry. The U.S. federal "Known Exploited Vulnerabilities" catalog only adds CVEs that have been **observed exploited in the wild**. Federal civilian agencies are required to remediate by the published due date; the same prioritisation logic applies to any sensible enterprise SOC.

{('Vendor / Product: **' + vendor + '**') if vendor else ''}

## Indicators of Compromise

- {cve} — match against your vulnerability scanner

## MITRE ATT&CK

- **T1190 — Exploit Public-Facing Application** (KEV implies active exploitation against exposed assets)

## Recommended hunts

Standard asset-exposure hunt — the canonical Splunk SPL and Defender KQL
live once in [`../_TEMPLATES.md#asset-exposure`](../_TEMPLATES.md#asset-exposure).
Substitute this CVE wherever the template references `<CVE>`:

- **CVE:** `{cve}`

## Why this matters

Anything in CISA KEV is *currently* being exploited. Even if your scanners say "not vulnerable" because of patches, it's worth one quick check across your fleet — patch lag is the silent killer. Federal due-date dates also frequently match the timing your organisation will be asked about by auditors / regulators.

## Source body

{body[:600]}{'…' if len(body) > 600 else ''}
"""


def _news_briefing(article, ind, ucs_pairs, techs, hit, sev):
    title = article["title"]
    src = ", ".join(article.get("sources", []) or [article.get("source", "")])
    pub = article.get("published", "")
    body = article.get("raw_body", "")
    link = article.get("link", "")

    ioc_lines = []
    for cve in ind.get("cves", []) or []:
        ioc_lines.append(f"- **CVE:** `{cve}`")
    for ip in ind.get("ips", []) or []:
        ioc_lines.append(f"- **IPv4 (defanged):** `{ip}`")
    for d in ind.get("domains", []) or []:
        ioc_lines.append(f"- **Domain (defanged):** `{d}`")
    for h in ind.get("sha256", []) or []:
        ioc_lines.append(f"- **SHA256:** `{h}`")
    for h in ind.get("sha1", []) or []:
        ioc_lines.append(f"- **SHA1:** `{h}`")
    for h in ind.get("md5", []) or []:
        ioc_lines.append(f"- **MD5:** `{h}`")
    if not ioc_lines:
        ioc_lines.append(
            "- _No high-fidelity IOCs in the RSS summary._ "
            "If the source publishes a technical write-up with defanged IOCs in the body, "
            "those would be picked up automatically on the next pipeline run."
        )

    tech_lines = []
    for tid, name in techs:
        tech_lines.append(f"- **{tid}**" + (f" — {name}" if name else ""))
    if not tech_lines:
        tech_lines.append("- _Narrative-keyword inference returned no technique mappings; review article for ATT&CK relevance manually._")

    # Compact rendering for the three IOC-substitution use cases. The full
    # SPL/KQL bodies are identical across hundreds of briefings — only the IOC
    # list differs. Inlining the full body on every briefing was redundant
    # noise. We emit a one-paragraph entry with the IOC list and link to the
    # canonical SPL/KQL in `briefings/_TEMPLATES.md`.
    BOILERPLATE_TITLES = {
        UC_VULN_EXPOSURE.title: ("asset-exposure", "cves",   "CVE(s)"),
        UC_NETWORK_IOC.title:   ("network-ioc",    "ipdom",  "IP / domain IOC(s)"),
        UC_HASH_IOC.title:      ("hash-ioc",       "hashes", "file hash IOC(s)"),
    }

    # Sort: LLM-driven article-bespoke UCs first (these read the actual
    # article and tailor a detection to the specific TTP, so they're the
    # highest-priority items for the analyst), then everything else in the
    # order rules fired them.
    def _llm_first(pair):
        _v, _u = pair
        return 0 if (_u.title or "").startswith("[LLM]") else 1
    ucs_pairs = sorted(ucs_pairs, key=_llm_first)

    uc_blocks = []
    boilerplate_seen = []
    for uc_var, uc in ucs_pairs:
        if uc.title in BOILERPLATE_TITLES:
            anchor, kind, label = BOILERPLATE_TITLES[uc.title]
            if kind == "cves":
                items = ind.get("cves", []) or []
            elif kind == "ipdom":
                items = (ind.get("ips", []) or []) + (ind.get("domains", []) or [])
            else:
                items = (ind.get("sha256", []) or []) + (ind.get("sha1", []) or []) + (ind.get("md5", []) or [])
            boilerplate_seen.append((uc, anchor, label, items))
            continue
        spl = parameterize(uc.splunk_spl, ind) if uc.splunk_spl else ""
        kql = parameterize(uc.defender_kql, ind) if uc.defender_kql else ""
        block = f"""### {uc.title}

`{uc_var}` · phase: **{uc.kill_chain}** · confidence: **{uc.confidence}**
"""
        if spl:
            block += f"\n**Splunk SPL (CIM):**\n```spl\n{spl.strip()}\n```\n"
        if kql:
            block += f"\n**Defender KQL:**\n```kql\n{kql.strip()}\n```\n"
        uc_blocks.append(block)

    boilerplate_seen = [bs for bs in boilerplate_seen if bs[3]]
    if boilerplate_seen:
        compact_lines = ["### IOC-driven hunts (use shared templates)\n"]
        compact_lines.append(
            "These are standard IOC-substitution hunts — the canonical SPL "
            "and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we "
            "don't repeat the same boilerplate on every CVE / hash / "
            "network-IOC briefing.\n"
        )
        for uc, anchor, label, items in boilerplate_seen:
            ioc_inline = ", ".join(f"`{i}`" for i in items[:8])
            more = f" _(+{len(items) - 8} more)_" if len(items) > 8 else ""
            compact_lines.append(
                f"- **{uc.title}** ([template](../_TEMPLATES.md#{anchor}))"
                f" — phase: **{uc.kill_chain}**, confidence: **{uc.confidence}**\n"
                f"  - {label}: {ioc_inline}{more}\n"
            )
        uc_blocks.append("\n".join(compact_lines))

    uc_section = "\n".join(uc_blocks) if uc_blocks else (
        "_No actionable hunts can be derived from the RSS summary alone. "
        "The article may still warrant manual review — open the source link "
        "for actor attribution, IOCs in the body, and TTP detail._\n"
    )

    return f"""# [{sev.upper()}] {title}

**Source:** {src}
**Published:** {pub}
**Article:** {link}

## Threat Profile

{(body[:500] + ('…' if len(body) > 500 else '')) if body else '_(no summary)_'}

## Indicators of Compromise (high-fidelity only)

{chr(10).join(ioc_lines)}

## MITRE ATT&CK Techniques

{chr(10).join(tech_lines)}

## Kill chain phases observed

{', '.join(sorted(hit)) or '_(none detected from narrative keywords)_'}

## Recommended hunts

{uc_section}

## Why this matters

Severity classified as **{sev.upper()}** based on: {('CVE present, ' if ind.get('cves') else '')}{'IOCs present, ' if any(ind.get(k) for k in ('ips','domains','sha256','sha1','md5')) else ''}{len(ucs_pairs)} use case(s) fired, {len(techs)} technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
"""


CURATED_MARKER = "<!-- curated:true -->"


def _write_briefing_templates():
    """Emit the canonical SPL/KQL for the three IOC-substitution use cases.

    These hunts are identical across hundreds of briefings — only the IOC
    list changes. Centralising them here keeps individual briefings focused
    on what's *unique* about each story (actor attribution, TTP detail,
    sector context) instead of repeating boilerplate.
    """
    md = """# Shared Detection Templates

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
"""
    (BRIEFINGS_DIR / "_TEMPLATES.md").write_text(md, encoding="utf-8")


def _emit_share_stub(path, title: str, description: str, target: str):
    """Write a tiny HTML redirect stub at `path` whose <head> carries
    rich og:*/twitter:* meta tags. Bots scrape these for the unfurl
    preview; humans get redirected to `target` (the in-app hash URL)
    via meta-refresh + JS in <50 ms. Idempotent — overwrites cleanly."""
    desc_short = (description or "").strip()
    if len(desc_short) > 280:
        desc_short = desc_short[:277].rstrip() + "..."
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(desc_short)}">
<link rel="canonical" href="{html.escape(target)}">
<meta property="og:type" content="article">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(desc_short)}">
<meta property="og:url" content="{html.escape(target)}">
<meta property="og:site_name" content="Clankerusecase">
<meta property="og:image" content="https://clankerusecase.com/logo.png">
<meta property="og:image:alt" content="Clankerusecase mascot">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{html.escape(title)}">
<meta name="twitter:description" content="{html.escape(desc_short)}">
<meta name="twitter:image" content="https://clankerusecase.com/logo.png">
<meta http-equiv="refresh" content="0; url={html.escape(target)}">
<style>body{{font-family:system-ui,sans-serif;background:#08090a;color:#e7e7eb;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}} a{{color:#7170ff;}}</style>
</head>
<body>
<p>Loading <a href="{html.escape(target)}">{html.escape(title)}</a> on Clankerusecase...</p>
<script>location.replace("{target.replace(chr(92), chr(92)*2).replace('"', chr(92)+chr(34))}");</script>
</body>
</html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def write_share_stubs(articles_meta, articles_raw_index, base_url: str = "https://clankerusecase.com"):
    """Emit per-article and per-UC redirect stubs at:
        share/article/<art-slug>.html
        share/uc/<uc-slug>.html
    so chat apps that paste these URLs render specific previews instead
    of the generic site OG card. Wipes share/ first so deletes propagate
    when articles rotate out of the window."""
    share_dir = Path(__file__).parent / "share"
    if share_dir.exists():
        import shutil
        shutil.rmtree(share_dir)
    art_dir = share_dir / "article"
    uc_dir = share_dir / "uc"
    art_dir.mkdir(parents=True, exist_ok=True)
    uc_dir.mkdir(parents=True, exist_ok=True)

    art_n = uc_n = 0
    seen_uc_slugs: set[str] = set()
    for am in articles_meta:
        a = articles_raw_index.get(am["id"])
        if not a:
            continue
        title = a.get("title") or "Article"
        summary = a.get("summary") or ""
        pub = am.get("published") or ""
        aslug = _art_slug(a, pub)
        target = f"{base_url}/#article-{aslug}"
        try:
            _emit_share_stub(art_dir / f"{aslug}.html", title + " — Clankerusecase",
                             summary, target)
            art_n += 1
        except OSError:
            # Slug too long for filesystem? Fall back gracefully.
            pass

        for _uc_var, uc in am.get("ucs", []) or []:
            usl = _uc_slug(uc)
            if usl in seen_uc_slugs:
                # Same UC reused across articles — first emit wins.
                continue
            seen_uc_slugs.add(usl)
            uctitle = (uc.title or "Use case").lstrip("[LLM] ").strip() or "Use case"
            ucdesc = (uc.description or "")
            _emit_share_stub(uc_dir / f"{usl}.html", uctitle + " — Clankerusecase UC",
                             ucdesc, f"{base_url}/#uc-{usl}")
            uc_n += 1
    print(f"[*] Share stubs written: {art_n} articles + {uc_n} UCs  ->  share/")


# =============================================================================
# Per-technique landing pages — one indexable HTML page per MITRE ATT&CK
# technique, aggregating UCs that cover it + articles that cite it.
# =============================================================================

# Stylesheet shared by every technique page. Lean — no JS, single inline
# <style> block. Pages are static; the dynamic site lives at /index.html.
_TECH_PAGE_STYLE = """
:root{--bg:#08090a;--panel:#16171b;--panel2:#1f2024;--text:#f7f8f8;--muted:#8a8f98;
--muted2:#62656a;--accent:#7170ff;--accent2:#9b8afb;--ok:#4cb782;--warn:#e2a93f;
--bad:#eb5757;--border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.12);
--code:#1a1b1e;--mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:radial-gradient(1200px 500px at 50% -10%,rgba(113,112,255,0.06),transparent 60%),var(--bg);
background-attachment:fixed;color:var(--text);
font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
font-size:14px;line-height:1.6;letter-spacing:-0.005em;
-webkit-font-smoothing:antialiased}
a{color:var(--accent2);text-decoration:none}a:hover{color:var(--accent);text-decoration:underline}
header.tp{position:sticky;top:0;z-index:50;background:rgba(8,9,10,0.85);
backdrop-filter:blur(16px) saturate(160%);border-bottom:1px solid var(--border);
padding:14px 28px;display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px;font-weight:600;font-size:17px}
.brand img{width:32px;height:32px;border-radius:7px;border:1px solid var(--border2)}
.brand .sub{color:var(--muted);font-weight:500;font-size:12px}
.back{margin-left:auto;color:var(--muted);font-size:12.5px;border:1px solid var(--border);
padding:6px 12px;border-radius:5px}
.back:hover{color:var(--text);border-color:var(--border2);background:var(--panel)}
main{max-width:1080px;margin:0 auto;padding:32px 28px}
.crumb{font-size:11.5px;color:var(--muted2);font-family:var(--mono);
letter-spacing:0.04em;text-transform:uppercase;margin-bottom:14px}
.crumb a{color:var(--muted)}.crumb .sep{margin:0 8px;color:var(--border2)}
h1.title{font-size:30px;line-height:1.18;margin:0 0 6px 0;font-weight:600;letter-spacing:-0.018em}
h1 .tid{font-family:var(--mono);font-size:18px;color:var(--accent2);margin-right:12px;
padding:4px 10px;border-radius:5px;background:rgba(113,112,255,0.10);
border:1px solid rgba(113,112,255,0.30);vertical-align:middle}
.lead{color:var(--muted);font-size:15px;margin:8px 0 18px 0;max-width:820px}
.tactic-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px}
.tactic-pill{font-size:11.5px;font-family:var(--mono);letter-spacing:0.02em;
padding:5px 11px;border-radius:99px;background:rgba(113,112,255,0.10);
color:var(--accent2);border:1px solid rgba(113,112,255,0.30)}
.stats{display:flex;flex-wrap:wrap;gap:18px;padding:14px 18px;
background:var(--panel);border:1px solid var(--border);border-radius:8px;
margin-bottom:24px}
.stats .stat{display:flex;flex-direction:column;gap:2px}
.stats .n{font-size:22px;font-weight:600;color:var(--accent2)}
.stats .l{font-size:11px;color:var(--muted2);font-family:var(--mono);
letter-spacing:0.04em;text-transform:uppercase}
.section{margin:28px 0}
.section h2{font-size:13px;font-family:var(--mono);letter-spacing:0.06em;
text-transform:uppercase;color:var(--muted);margin:0 0 14px 0;padding-bottom:8px;
border-bottom:1px solid var(--border)}
.uc-card{background:var(--panel);border:1px solid var(--border);border-radius:7px;
padding:14px 16px;margin-bottom:10px;transition:border-color 0.12s,background 0.12s}
.uc-card:hover{border-color:var(--accent);background:var(--panel2)}
.uc-card .t{font-weight:500;font-size:14.5px;display:block;color:var(--text);margin-bottom:4px}
.uc-card .meta{font-size:11.5px;color:var(--muted2);display:flex;flex-wrap:wrap;gap:10px;
align-items:center;font-family:var(--mono);letter-spacing:0.02em}
.uc-card .src{padding:1px 8px;border-radius:99px;font-weight:600;font-size:10px;
text-transform:uppercase;letter-spacing:0.06em}
.src.internal{background:rgba(76,183,130,0.16);color:#9bdfc1;border:1px solid rgba(76,183,130,0.40)}
.src.bespoke{background:rgba(155,138,251,0.14);color:var(--accent2);border:1px solid rgba(155,138,251,0.36)}
.src.escu{background:rgba(226,169,63,0.14);color:var(--warn);border:1px solid rgba(226,169,63,0.36)}
.uc-card .pl{display:inline-flex;gap:3px;margin-left:auto}
.uc-card .pl span{font-size:9.5px;font-weight:700;width:18px;height:18px;
display:inline-flex;align-items:center;justify-content:center;border-radius:4px;
font-family:var(--mono)}
.pl .pl-d{background:rgba(80,200,160,0.18);color:#9bdfc1}
.pl .pl-s{background:rgba(110,160,255,0.18);color:#a8c8ff}
.pl .pl-g{background:rgba(255,170,90,0.18);color:#ffcc99}
.pl .pl-p{background:rgba(220,120,200,0.18);color:#f5b8e0}
.pl .pl-D{background:rgba(120,90,200,0.20);color:#c8aff8}
.art-row{padding:10px 0;border-bottom:1px solid var(--border);font-size:13.5px}
.art-row:last-child{border:0}
.art-row .at{display:block;color:var(--text);margin-bottom:3px}
.art-row .am{font-size:11.5px;color:var(--muted2);font-family:var(--mono)}
.sev{display:inline-block;padding:1px 7px;border-radius:99px;font-size:10px;
font-family:var(--mono);font-weight:700;text-transform:uppercase;
letter-spacing:0.05em;margin-right:8px}
.sev.crit{background:rgba(235,87,87,0.18);color:#ff8888;border:1px solid rgba(235,87,87,0.40)}
.sev.high{background:rgba(226,169,63,0.16);color:var(--warn);border:1px solid rgba(226,169,63,0.36)}
.sev.med{background:rgba(113,112,255,0.14);color:var(--accent2);border:1px solid rgba(113,112,255,0.34)}
.sev.low{background:rgba(76,183,130,0.14);color:#9bdfc1;border:1px solid rgba(76,183,130,0.34)}
.subs{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 8px 0}
.subs a{font-size:11.5px;font-family:var(--mono);padding:4px 10px;border-radius:5px;
background:var(--panel);border:1px solid var(--border);color:var(--text)}
.subs a:hover{border-color:var(--accent);text-decoration:none;background:var(--panel2)}
.parent-link{font-size:12.5px;color:var(--muted);margin:8px 0}
.cta{display:flex;gap:10px;margin:18px 0 24px 0;flex-wrap:wrap}
.cta a{padding:8px 14px;border-radius:6px;font-size:12.5px;font-weight:500;
border:1px solid var(--border2);background:var(--panel);color:var(--text)}
.cta a.primary{background:rgba(113,112,255,0.16);border-color:rgba(113,112,255,0.40);
color:var(--accent2)}
.cta a:hover{border-color:var(--accent);text-decoration:none}
.empty{padding:18px;text-align:center;color:var(--muted2);font-size:13px;
background:var(--panel);border:1px dashed var(--border2);border-radius:7px}
footer{padding:32px 28px;text-align:center;color:var(--muted2);font-size:11.5px;
border-top:1px solid var(--border);margin-top:48px;font-family:var(--mono)}
"""


_PL_BADGE_LABELS = {
    "d": ("pl-d", "D", "Defender KQL"),
    "s": ("pl-s", "S", "Sentinel KQL"),
    "g": ("pl-g", "Σ", "Sigma"),
    "p": ("pl-p", "P", "Splunk SPL"),
    "D": ("pl-D", "DD", "Datadog Cloud SIEM"),
}


def _render_technique_page(tid: str, technique_view: dict, matrix_data: dict,
                            base_url: str = "https://clankerusecase.com") -> str:
    """One static HTML page summarising one MITRE ATT&CK technique.

    Aggregates: name + ID + tactics, kill-chain context, sub-techniques (or
    parent), every UC that covers this technique with platform badges, every
    article citing it, and links out to MITRE's canonical doc + the in-app
    matrix view + Detection Library filtered to this technique."""
    tinfo = technique_view.get(tid, {})
    name = tinfo.get("name", tid)
    parent_tid = tinfo.get("parent")
    subs = tinfo.get("subs") or []
    tactics = tinfo.get("tactics") or []
    is_sub = bool(tinfo.get("is_sub"))

    ucs = matrix_data.get("tech_ucs", {}).get(tid, [])
    arts = matrix_data.get("tech_arts", {}).get(tid, [])
    uc_records = matrix_data.get("ucs") or []
    art_records = matrix_data.get("arts") or []

    # Tactic row
    tactic_pills = "".join(
        f'<span class="tactic-pill">{html.escape(TACTIC_DISPLAY.get(t, t))}</span>'
        for t in tactics
    )

    # Sub-techniques or parent link
    sub_block = ""
    if subs:
        sub_links = "".join(
            f'<a href="{html.escape(s)}.html">{html.escape(s)} · '
            f'{html.escape(technique_view.get(s, {}).get("name", s))}</a>'
            for s in subs
        )
        sub_block = f'<div class="section"><h2>Sub-techniques ({len(subs)})</h2><div class="subs">{sub_links}</div></div>'
    elif is_sub and parent_tid:
        pname = technique_view.get(parent_tid, {}).get("name", parent_tid)
        sub_block = (
            f'<div class="parent-link">↑ Parent technique: '
            f'<a href="{html.escape(parent_tid)}.html">{html.escape(parent_tid)} · '
            f'{html.escape(pname)}</a></div>'
        )

    # UC list
    uc_html_parts = []
    for uc_idx in ucs:
        if uc_idx >= len(uc_records):
            continue
        uc = uc_records[uc_idx]
        title = uc.get("t", "Untitled")
        src = uc.get("src", "internal")
        pl = uc.get("pl", "") or ""
        # Platform badges from the pl string
        badges = []
        for i, ch in enumerate(pl):
            if ch == "-":
                continue
            cls, lbl, full = _PL_BADGE_LABELS.get(ch, ("", ch, ch))
            if cls:
                badges.append(f'<span class="{cls}" title="{html.escape(full)}">{html.escape(lbl)}</span>')
        platforms_html = '<span class="pl">' + "".join(badges) + '</span>' if badges else ""
        # Source pill
        src_label = {"internal": "Internal", "bespoke": "Bespoke", "escu": "ESCU"}.get(src, src.title())
        # Tier
        tier = uc.get("tier", "")
        tier_html = f' · {html.escape(tier)}' if tier else ""
        # Phase
        ph = uc.get("ph", "")
        # Link target — internal UCs use the variable name; bespoke don't
        # have a stable hash slug here (would need _uc_slug computation).
        # Point to the in-app filtered Library by technique instead.
        href = f"{base_url}/#uc-search-{html.escape(tid)}"
        uc_html_parts.append(
            f'<a class="uc-card" href="{href}">'
            f'  <span class="t">{html.escape(title)}</span>'
            f'  <span class="meta">'
            f'    <span class="src {src}">{html.escape(src_label)}</span>'
            f'    {ph}{tier_html}'
            f'    {platforms_html}'
            f'  </span>'
            f'</a>'
        )
    if uc_html_parts:
        uc_section = (
            f'<div class="section"><h2>Use cases covering this technique ({len(ucs)})</h2>'
            f'{"".join(uc_html_parts)}</div>'
        )
    else:
        uc_section = (
            f'<div class="section"><h2>Use cases covering this technique</h2>'
            f'<div class="empty">No use cases yet — this technique is in the matrix '
            f'but no UC explicitly maps to it. Articles citing it may still appear below.</div></div>'
        )

    # Articles
    art_html_parts = []
    for a_idx in arts:
        if a_idx >= len(art_records):
            continue
        ar = art_records[a_idx]
        atitle = ar.get("title", "")
        sev = ar.get("sev", "low")
        # We don't have a published date or link in the matrix art record.
        # Use the article id (e.g. "art-23") for an in-app deeplink.
        aid = ar.get("id", "")
        href = f"{base_url}/#{html.escape(aid)}" if aid else f"{base_url}/"
        art_html_parts.append(
            f'<div class="art-row">'
            f'  <a class="at" href="{href}"><span class="sev {sev}">{html.escape(sev)}</span>'
            f'  {html.escape(atitle)}</a>'
            f'  <span class="am">{html.escape(aid)}</span>'
            f'</div>'
        )
    if art_html_parts:
        art_section = (
            f'<div class="section"><h2>Articles citing this technique ({len(arts)})</h2>'
            f'{"".join(art_html_parts)}</div>'
        )
    else:
        art_section = ""

    # CTAs
    mitre_url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/")
    cta = (
        f'<div class="cta">'
        f'  <a class="primary" href="{base_url}/#technique-{html.escape(tid)}">View on the matrix →</a>'
        f'  <a href="{base_url}/#uc-search-{html.escape(tid)}">Filter Detection Library</a>'
        f'  <a href="{html.escape(mitre_url)}" target="_blank" rel="noopener">MITRE official spec ↗</a>'
        f'</div>'
    )

    # Lead paragraph + meta description (used both visibly and in <meta>)
    primary_tactic = TACTIC_DISPLAY.get(tactics[0], tactics[0]) if tactics else "MITRE ATT&CK"
    n_ucs = len(ucs)
    n_arts = len(arts)
    uc_word = "use case" if n_ucs == 1 else "use cases"
    art_word = "article" if n_arts == 1 else "articles"
    arts_clause = f" and <strong>{n_arts}</strong> threat-intel {art_word} citing it" if n_arts else ""
    tactic_clause = f" in the {html.escape(primary_tactic)} tactic" if tactics else ""
    lead = (
        f"<strong>{html.escape(tid)}</strong> — {html.escape(name)} is a MITRE ATT&CK "
        f"technique{tactic_clause}. "
        f"Clankerusecase tracks <strong>{n_ucs}</strong> detection {uc_word} covering it"
        f"{arts_clause}."
    )
    meta_desc = (
        f"{tid} {name} — MITRE ATT&CK technique. {n_ucs} detection use cases, "
        f"{n_arts} threat-intel articles. Defender KQL, Sentinel KQL, Sigma, "
        f"Splunk SPL, and Datadog Cloud SIEM coverage."
    )

    canonical = f"{base_url}/techniques/{tid}.html"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(tid)} · {html.escape(name)} — Clankerusecase MITRE ATT&CK detection coverage</title>
<meta name="description" content="{html.escape(meta_desc)}">
<link rel="canonical" href="{html.escape(canonical)}">
<link rel="icon" type="image/png" href="{base_url}/logo.png">
<meta property="og:type" content="article">
<meta property="og:title" content="{html.escape(tid)} · {html.escape(name)} — Clankerusecase">
<meta property="og:description" content="{html.escape(meta_desc)}">
<meta property="og:url" content="{html.escape(canonical)}">
<meta property="og:image" content="{base_url}/logo.png">
<meta property="og:site_name" content="Clankerusecase">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{html.escape(tid)} · {html.escape(name)}">
<meta name="twitter:description" content="{html.escape(meta_desc)}">
<script type="application/ld+json">
{{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "{html.escape(tid)} · {html.escape(name)}",
  "description": "{html.escape(meta_desc)}",
  "url": "{canonical}",
  "publisher": {{ "@type": "Organization", "name": "Clankerusecase",
                  "url": "{base_url}/" }},
  "about": {{ "@type": "DefinedTerm", "name": "{html.escape(name)}",
              "termCode": "{html.escape(tid)}",
              "url": "{html.escape(mitre_url)}" }}
}}
</script>
<style>{_TECH_PAGE_STYLE}</style>
</head>
<body>
<header class="tp">
  <a href="{base_url}/" class="brand">
    <img src="{base_url}/logo.png" alt="">
    <div>Clankerusecase<div class="sub">MITRE ATT&CK detection coverage</div></div>
  </a>
  <a href="{base_url}/" class="back">← Back to main site</a>
</header>
<main>
  <div class="crumb">
    <a href="{base_url}/">Home</a><span class="sep">/</span>
    <a href="{base_url}/#tab-attack-matrix">MITRE Matrix</a><span class="sep">/</span>
    {(html.escape(primary_tactic) + '<span class="sep">/</span>') if tactics else ''}
    {html.escape(tid)}
  </div>
  <h1 class="title"><span class="tid">{html.escape(tid)}</span>{html.escape(name)}</h1>
  <p class="lead">{lead}</p>
  {("<div class='tactic-row'>" + tactic_pills + "</div>") if tactic_pills else ""}
  {cta}
  <div class="stats">
    <div class="stat"><span class="n">{n_ucs}</span><span class="l">Use cases</span></div>
    <div class="stat"><span class="n">{n_arts}</span><span class="l">Articles</span></div>
    <div class="stat"><span class="n">{len(subs)}</span><span class="l">Sub-techniques</span></div>
    <div class="stat"><span class="n">{len(tactics)}</span><span class="l">Tactic{'s' if len(tactics) != 1 else ''}</span></div>
  </div>
  {sub_block}
  {uc_section}
  {art_section}
</main>
<footer>
  Auto-generated from the Clankerusecase use-case catalogue. Re-built every 2 hours.
  <br>Reference: <a href="{html.escape(mitre_url)}" target="_blank" rel="noopener">attack.mitre.org/techniques/{html.escape(tid.replace('.', '/'))}</a>
</footer>
</body>
</html>
"""


def write_technique_pages(matrix_data: dict, base_url: str = "https://clankerusecase.com") -> int:
    """Emit one static HTML page per technique under techniques/. Returns
    the count written. Wipes the directory first so deletes propagate."""
    if not matrix_data:
        return 0
    technique_view = matrix_data.get("techniques") or {}
    out_dir = Path(__file__).parent / "techniques"
    if out_dir.exists():
        import shutil
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for tid in technique_view:
        try:
            page = _render_technique_page(tid, technique_view, matrix_data, base_url)
            (out_dir / f"{tid}.html").write_text(page, encoding="utf-8")
            written += 1
        except OSError:
            # Skip if filesystem chokes on the tid (shouldn't happen with T-IDs)
            pass
    print(f"[*] Technique landing pages: {written}  ->  techniques/")
    return written


# =============================================================================
# Per-actor landing pages — mirror of the technique pages, one indexable
# HTML hub per tracked threat actor (APT29, Lazarus, ScarCruft, etc).
# =============================================================================

def _actor_slug(name: str) -> str:
    """URL slug — lowercase, alphanumeric + dashes."""
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s[:80] or "unknown"


def _render_actor_page(actor: dict, technique_view: dict,
                        base_url: str = "https://clankerusecase.com") -> str:
    """One static HTML page per threat actor — mirrors the technique-page
    pattern. Aggregates: profile (country, motivation, aliases, MITRE ID),
    stats (UCs, articles, techniques, IOCs), top techniques (cross-linked
    to the per-technique pages), UC list, article list, IOC summary, and
    the MITRE official-spec link when MITRE-attributed."""
    name = actor.get("name", "Unknown actor")
    country = actor.get("country") or ""
    flag = actor.get("flag") or ""
    motivation = actor.get("motivation") or ""
    aliases = actor.get("aliases") or []
    mitre_id = actor.get("mitre_id") or ""
    mitre_desc = actor.get("mitre_description") or ""
    techs = actor.get("techs") or []
    top_techs = actor.get("top_techs") or techs[:3]
    iocs = actor.get("iocs") or {}
    articles = actor.get("articles") or []
    ucs = actor.get("ucs") or []
    first_seen = actor.get("first_seen") or ""
    last_seen = actor.get("last_seen") or ""
    is_mitre_only = actor.get("is_mitre_only", False)

    slug = _actor_slug(name)

    # Aliases pill row
    aliases_html = ""
    if aliases:
        aliases_html = (
            '<div class="section"><h2>Known aliases</h2><div class="subs">'
            + "".join(f'<span style="font-size:12px;font-family:var(--mono);'
                      f'padding:5px 11px;border-radius:5px;background:var(--panel);'
                      f'border:1px solid var(--border);">{html.escape(a)}</span>'
                      for a in aliases)
            + "</div></div>"
        )

    # Top techniques — cross-link to /techniques/<TID>.html
    top_tech_html = ""
    if top_techs:
        items = []
        for tid in top_techs:
            tname = technique_view.get(tid, {}).get("name", tid)
            items.append(
                f'<a href="../techniques/{html.escape(tid)}.html">'
                f'{html.escape(tid)} · {html.escape(tname)}</a>'
            )
        top_tech_html = (
            '<div class="section"><h2>Top techniques</h2><div class="subs">'
            + "".join(items) + "</div></div>"
        )

    # Full technique list when there are more than the top ones
    if len(techs) > len(top_techs):
        items = []
        for tid in techs:
            if tid in (top_techs or []):
                continue
            tname = technique_view.get(tid, {}).get("name", tid)
            items.append(
                f'<a href="../techniques/{html.escape(tid)}.html">'
                f'{html.escape(tid)} · {html.escape(tname)}</a>'
            )
        if items:
            top_tech_html += (
                '<div class="section"><h2>All other tracked techniques</h2>'
                '<div class="subs" style="max-height:240px;overflow:auto;">'
                + "".join(items) + "</div></div>"
            )

    # UC list — show titles + sources + platform badges
    uc_parts = []
    for uc in ucs[:50]:
        title = uc.get("title", "Untitled UC")
        # Build platform badges from the UC's available bodies
        badges = []
        if uc.get("defender_kql"):
            badges.append('<span class="pl-d" title="Defender KQL">D</span>')
        if uc.get("sentinel_kql"):
            badges.append('<span class="pl-s" title="Sentinel KQL">S</span>')
        if uc.get("sigma_yaml"):
            badges.append('<span class="pl-g" title="Sigma">Σ</span>')
        if uc.get("splunk_spl"):
            badges.append('<span class="pl-p" title="Splunk SPL">P</span>')
        if uc.get("datadog_query"):
            badges.append('<span class="pl-D" title="Datadog Cloud SIEM">DD</span>')
        platforms_html = '<span class="pl">' + "".join(badges) + '</span>' if badges else ""
        # Source pill — bespoke (article-bound), llm (actor-profile), or mitre-match
        kind = uc.get("source_kind") or ""
        if kind == "actor-bespoke":
            src_label, src_cls = "LLM · profile", "bespoke"
        elif uc.get("is_mitre_match"):
            src_label, src_cls = "MITRE match", "internal"
        elif title.startswith("[LLM]"):
            src_label, src_cls = "Bespoke", "bespoke"
        else:
            src_label, src_cls = "Internal", "internal"
        href = f"{base_url}/#actor-{html.escape(slug)}"
        uc_parts.append(
            f'<a class="uc-card" href="{href}">'
            f'  <span class="t">{html.escape(title)}</span>'
            f'  <span class="meta">'
            f'    <span class="src {src_cls}">{html.escape(src_label)}</span>'
            f'    {platforms_html}'
            f'  </span>'
            f'</a>'
        )
    if uc_parts:
        uc_section = (
            f'<div class="section"><h2>Detection use cases ({len(ucs)})</h2>'
            f'{"".join(uc_parts)}'
            + (f'<p style="color:var(--muted2);font-size:12px;margin-top:12px;">'
               f'Showing the top 50 of {len(ucs)} — open the actor on the main site '
               f'for the full list.</p>' if len(ucs) > 50 else "")
            + '</div>'
        )
    else:
        uc_section = (
            '<div class="section"><h2>Detection use cases</h2>'
            '<div class="empty">No use cases yet — this actor is in the catalogue '
            'but no UC has been authored or auto-generated for them. Check the '
            'main Threat Actors tab for live updates.</div></div>'
        )

    # Article list
    art_parts = []
    for a in articles[:30]:
        atitle = a.get("title", "")
        link = a.get("link", "")
        date = a.get("published") or a.get("date") or ""
        source = a.get("source") or ""
        sev = (a.get("sev") or "low").lower()
        href = link or f"{base_url}/"
        art_parts.append(
            f'<div class="art-row">'
            f'  <a class="at" href="{html.escape(href)}" target="_blank" rel="noopener">'
            f'    <span class="sev {sev}">{html.escape(sev)}</span>'
            f'    {html.escape(atitle)}</a>'
            f'  <span class="am">{html.escape(source)} · {html.escape(date)}</span>'
            f'</div>'
        )
    if art_parts:
        art_section = (
            f'<div class="section"><h2>Threat-intel articles ({len(articles)})</h2>'
            f'{"".join(art_parts)}'
            + (f'<p style="color:var(--muted2);font-size:12px;margin-top:12px;">'
               f'Showing the most recent 30 of {len(articles)}.</p>' if len(articles) > 30 else "")
            + '</div>'
        )
    else:
        art_section = ""

    # IOC summary
    ioc_parts = []
    for kind, label, items in [
        ("domains", "Domains", iocs.get("domains") or []),
        ("ips", "IP addresses", iocs.get("ips") or []),
        ("sha256", "SHA-256 hashes", iocs.get("sha256") or []),
        ("cves", "CVEs", iocs.get("cves") or []),
    ]:
        if not items:
            continue
        chips = " ".join(
            f'<code style="font-size:11px;font-family:var(--mono);'
            f'padding:2px 7px;border-radius:4px;background:var(--panel);'
            f'border:1px solid var(--border);color:var(--muted);">{html.escape(str(i))[:24]}</code>'
            for i in items[:25]
        )
        more = f' <span style="color:var(--muted2);font-size:11px;">+{len(items) - 25} more</span>' if len(items) > 25 else ""
        ioc_parts.append(
            f'<div style="margin-bottom:14px;">'
            f'  <h3 style="font-size:12px;font-family:var(--mono);'
            f'letter-spacing:0.04em;text-transform:uppercase;color:var(--muted);'
            f'margin:0 0 8px 0;">{html.escape(label)} ({len(items)})</h3>'
            f'  <div style="display:flex;flex-wrap:wrap;gap:6px;">{chips}{more}</div>'
            f'</div>'
        )
    ioc_section = (
        f'<div class="section"><h2>Tracked indicators</h2>{"".join(ioc_parts)}</div>'
        if ioc_parts else ""
    )

    # CTAs
    mitre_cta = ""
    if mitre_id:
        mitre_cta = (
            f'<a href="https://attack.mitre.org/groups/{html.escape(mitre_id)}/" '
            f'target="_blank" rel="noopener">MITRE ATT&CK group spec ({mitre_id}) ↗</a>'
        )
    cta = (
        f'<div class="cta">'
        f'  <a class="primary" href="{base_url}/#actor-{html.escape(slug)}">View full actor card →</a>'
        f'  <a href="{base_url}/#tab-actors">All threat actors</a>'
        f'  {mitre_cta}'
        f'</div>'
    )

    # Lead paragraph
    n_ucs = len(ucs)
    n_arts = len(articles)
    n_techs = len(techs)
    activity_window = ""
    if first_seen and last_seen:
        activity_window = f" Active in our corpus from {html.escape(first_seen)} to {html.escape(last_seen)}."
    elif first_seen or last_seen:
        activity_window = f" Active around {html.escape(first_seen or last_seen)}."

    motiv_clause = ""
    if motivation:
        motiv_clause = f" Primary motivation: <strong>{html.escape(motivation.title())}</strong>."
    country_clause = ""
    if country and not is_mitre_only:
        country_clause = f" Attributed to <strong>{html.escape(country)}</strong>."
    elif country:
        country_clause = f" {html.escape(country)}-aligned."

    lead = (
        f"<strong>{flag} {html.escape(name)}</strong> is a tracked threat actor in the "
        f"Clankerusecase corpus.{country_clause}{motiv_clause} "
        f"We map <strong>{n_ucs}</strong> detection use case"
        f"{'s' if n_ucs != 1 else ''} to this actor across <strong>{n_techs}</strong> "
        f"MITRE ATT&CK technique{'s' if n_techs != 1 else ''}, with "
        f"<strong>{n_arts}</strong> threat-intel article{'s' if n_arts != 1 else ''} "
        f"citing them.{activity_window}"
    )

    meta_desc_short = (
        f"{name} threat actor profile — {country or 'unknown attribution'}, "
        f"{n_ucs} detection use cases across Defender / Sentinel / Sigma / "
        f"Splunk / Datadog. {n_arts} cited articles, {n_techs} ATT&CK techniques."
    )[:280]

    canonical = f"{base_url}/actors/{slug}.html"
    title_text = f"{name}{(' (' + ', '.join(aliases[:3]) + ')') if aliases else ''} — Threat actor profile · Clankerusecase"

    # MITRE description block (if available and non-empty)
    mitre_block = ""
    if mitre_desc and len(mitre_desc.strip()) > 20:
        # Trim to first 800 chars for the SEO surface
        desc_short = mitre_desc.strip()
        if len(desc_short) > 800:
            desc_short = desc_short[:797].rstrip() + "…"
        mitre_block = (
            f'<div class="section"><h2>About this actor (MITRE)</h2>'
            f'<p style="color:var(--text);font-size:14px;line-height:1.7;'
            f'max-width:820px;">{html.escape(desc_short)}</p></div>'
        )

    sev_dist = actor.get("sev_dist") or {}
    sev_block = ""
    if any(sev_dist.values() if isinstance(sev_dist, dict) else []):
        # Tiny stat strip showing severity distribution of cited articles
        sev_pills = "".join(
            f'<span class="sev {k}" style="margin-right:6px;">{html.escape(k)} {v}</span>'
            for k, v in sev_dist.items() if v
        )
        sev_block = f'<div style="margin-bottom:18px;">{sev_pills}</div>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title_text)}</title>
<meta name="description" content="{html.escape(meta_desc_short)}">
<link rel="canonical" href="{html.escape(canonical)}">
<link rel="icon" type="image/png" href="{base_url}/logo.png">
<meta property="og:type" content="article">
<meta property="og:title" content="{html.escape(name)} — Threat actor profile · Clankerusecase">
<meta property="og:description" content="{html.escape(meta_desc_short)}">
<meta property="og:url" content="{html.escape(canonical)}">
<meta property="og:image" content="{base_url}/logo.png">
<meta property="og:site_name" content="Clankerusecase">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{html.escape(name)} — Threat actor profile">
<meta name="twitter:description" content="{html.escape(meta_desc_short)}">
<script type="application/ld+json">
{{
  "@context": "https://schema.org",
  "@type": "Person",
  "@id": "{canonical}",
  "name": "{html.escape(name)}",
  "alternateName": {__import__('json').dumps(aliases)},
  "description": "{html.escape(meta_desc_short)}",
  "url": "{canonical}",
  "publisher": {{ "@type": "Organization", "name": "Clankerusecase",
                  "url": "{base_url}/" }}{("," if mitre_id else "")}
  {('"sameAs": ["https://attack.mitre.org/groups/' + mitre_id + '/"]') if mitre_id else ''}
}}
</script>
<style>{_TECH_PAGE_STYLE}</style>
</head>
<body>
<header class="tp">
  <a href="{base_url}/" class="brand">
    <img src="{base_url}/logo.png" alt="">
    <div>Clankerusecase<div class="sub">Threat-actor profile</div></div>
  </a>
  <a href="{base_url}/" class="back">← Back to main site</a>
</header>
<main>
  <div class="crumb">
    <a href="{base_url}/">Home</a><span class="sep">/</span>
    <a href="{base_url}/#tab-actors">Threat Actors</a><span class="sep">/</span>
    {html.escape(name)}
  </div>
  <h1 class="title"><span class="tid">{flag}</span>{html.escape(name)}</h1>
  <p class="lead">{lead}</p>
  {sev_block}
  {cta}
  <div class="stats">
    <div class="stat"><span class="n">{n_ucs}</span><span class="l">Use cases</span></div>
    <div class="stat"><span class="n">{n_arts}</span><span class="l">Articles</span></div>
    <div class="stat"><span class="n">{n_techs}</span><span class="l">Techniques</span></div>
    <div class="stat"><span class="n">{len(iocs.get('domains', [])) + len(iocs.get('ips', [])) + len(iocs.get('sha256', []))}</span><span class="l">IOCs</span></div>
  </div>
  {mitre_block}
  {aliases_html}
  {top_tech_html}
  {uc_section}
  {art_section}
  {ioc_section}
</main>
<footer>
  Auto-generated from the Clankerusecase actor catalogue. Re-built every 2 hours.
  {('<br>Reference: <a href="https://attack.mitre.org/groups/' + html.escape(mitre_id) + '/" target="_blank" rel="noopener">attack.mitre.org/groups/' + html.escape(mitre_id) + '</a>') if mitre_id else ''}
</footer>
</body>
</html>
"""


def write_actor_pages(actors_serialisable: list, technique_view: dict,
                       base_url: str = "https://clankerusecase.com") -> int:
    """Emit one static HTML page per tracked threat actor under actors/.
    Returns the count written. Wipes the directory first so deletes
    propagate when actors rotate out of the corpus."""
    if not actors_serialisable:
        return 0
    out_dir = Path(__file__).parent / "actors"
    if out_dir.exists():
        import shutil
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    written = 0
    for actor in actors_serialisable:
        name = actor.get("name") or ""
        if not name:
            continue
        slug = _actor_slug(name)
        if slug in seen:
            continue
        seen.add(slug)
        try:
            page = _render_actor_page(actor, technique_view or {}, base_url)
            (out_dir / f"{slug}.html").write_text(page, encoding="utf-8")
            written += 1
        except (OSError, KeyError) as e:
            print(f"    [!] actor page failed for {name}: {str(e)[:80]}")
    print(f"[*] Actor landing pages: {written}  ->  actors/")
    return written


# =============================================================================
# Per-target landing pages — one indexable HTML hub per OS / cloud / SaaS
# (Linux, Windows, AWS, Azure, GCP, Kubernetes, M365, Okta, VCS, Identity,
# Web App, macOS). Mirrors the technique-page pattern for SEO surface area.
# =============================================================================

def _render_target_page(tag: str, label: str, icon: str, blurb: str,
                         matrix_data: dict,
                         base_url: str = "https://clankerusecase.com") -> str:
    """Render one HTML page summarising every UC tagged with the given
    target surface (windows, linux, aws, ...). The matrix carries the
    `tg` array per UC; this page filters on it and groups by kill-chain."""
    uc_records = matrix_data.get("ucs") or []
    art_records = matrix_data.get("arts") or []
    technique_view = matrix_data.get("techniques") or {}

    # Filter UCs that include this target tag
    matched_idxs = [u["i"] for u in uc_records if tag in (u.get("tg") or [])]
    matched = [uc_records[i] for i in matched_idxs if i < len(uc_records)]

    # Group by kill-chain phase. Same buckets the Library uses.
    PHASE_ORDER = ["recon", "delivery", "exploit", "install", "c2", "actions"]
    PHASE_LABELS = {
        "recon": "Reconnaissance", "delivery": "Delivery", "exploit": "Exploitation",
        "install": "Installation", "c2": "Command & Control", "actions": "Actions on Objectives",
    }
    by_phase: dict[str, list] = {p: [] for p in PHASE_ORDER}
    for u in matched:
        ph = (u.get("ph") or "actions").lower()
        if ph not in by_phase:
            ph = "actions"
        by_phase[ph].append(u)

    # Article cross-reference — every distinct article that any matched UC cites.
    art_idxs: set[int] = set()
    for u in matched:
        for a_idx in (u.get("arts") or []):
            art_idxs.add(a_idx)
    arts_for_target = [art_records[i] for i in sorted(art_idxs) if i < len(art_records)]

    # Top techniques across the matched UCs
    tech_counts: dict[str, int] = {}
    for u in matched:
        for tid in (u.get("techs") or []):
            tech_counts[tid] = tech_counts.get(tid, 0) + 1
    top_techs = sorted(tech_counts.items(), key=lambda kv: -kv[1])[:25]

    # Render UC cards grouped by phase
    phase_blocks: list[str] = []
    for ph in PHASE_ORDER:
        bucket = by_phase[ph]
        if not bucket:
            continue
        cards: list[str] = []
        for u in bucket[:200]:  # cap per-phase for page weight
            title = u.get("t", "Untitled")
            src = u.get("src", "internal")
            pl = u.get("pl", "") or ""
            badges: list[str] = []
            for ch in pl:
                if ch == "-":
                    continue
                cls, lbl, full = _PL_BADGE_LABELS.get(ch, ("", ch, ch))
                if cls:
                    badges.append(f'<span class="{cls}" title="{html.escape(full)}">{html.escape(lbl)}</span>')
            platforms_html = '<span class="pl">' + "".join(badges) + '</span>' if badges else ""
            src_label = {"internal": "Internal", "bespoke": "Bespoke", "escu": "ESCU"}.get(src, src.title())
            tier = u.get("tier", "")
            tier_html = f' · {html.escape(tier)}' if tier else ""
            href = f"{base_url}/#uc-{u.get('i')}"
            cards.append(
                f'<a class="uc-card" href="{href}">'
                f'  <span class="t">{html.escape(title)}</span>'
                f'  <span class="meta">'
                f'    <span class="src {src}">{html.escape(src_label)}</span>'
                f'    {ph}{tier_html}'
                f'    {platforms_html}'
                f'  </span>'
                f'</a>'
            )
        phase_blocks.append(
            f'<div class="section"><h2>{html.escape(PHASE_LABELS[ph])} ({len(bucket)})</h2>{"".join(cards)}</div>'
        )

    # Top techniques block
    tech_html = ""
    if top_techs:
        rows = "".join(
            f'<a href="{base_url}/techniques/{html.escape(tid)}.html">'
            f'<span class="tid-mini">{html.escape(tid)}</span>'
            f'<span class="tn">{html.escape(technique_view.get(tid, {}).get("name", tid))}</span>'
            f'<span class="cnt">{cnt}</span></a>'
            for tid, cnt in top_techs
        )
        tech_html = (
            f'<div class="section"><h2>Top techniques on {html.escape(label)} ({len(top_techs)})</h2>'
            f'<div class="subs">{rows}</div></div>'
        )

    # Articles section
    arts_html = ""
    if arts_for_target:
        # cap to prevent oversized pages
        arts_for_target = arts_for_target[:60]
        rows = "".join(
            f'<div class="art-row">'
            f'  <a class="at" href="{base_url}/#{html.escape(a.get("id",""))}">'
            f'    <span class="sev {a.get("sev","low")}">{html.escape(a.get("sev","low"))}</span>'
            f'    {html.escape(a.get("title",""))}'
            f'  </a>'
            f'</div>'
            for a in arts_for_target
        )
        arts_html = (
            f'<div class="section"><h2>Recent articles citing {html.escape(label)}-targeted detections</h2>'
            f'{rows}</div>'
        )

    # Stats / lead
    n_ucs = len(matched)
    n_arts = len(arts_for_target)
    n_techs = len(tech_counts)
    lead = (
        f"Clankerusecase tracks <strong>{n_ucs}</strong> detection use cases "
        f"covering the <strong>{html.escape(label)}</strong> attack surface "
        f"across <strong>{n_techs}</strong> MITRE ATT&CK techniques."
    )
    meta_desc = (
        f"{label} detection use cases — {n_ucs} SOC detections covering "
        f"{n_techs} MITRE ATT&CK techniques. Defender KQL, Sentinel KQL, "
        f"Sigma, Splunk SPL, and Datadog Cloud SIEM coverage for {label}."
    )
    canonical = f"{base_url}/targets/{tag}.html"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(label)} detection use cases — Clankerusecase</title>
<meta name="description" content="{html.escape(meta_desc)}">
<link rel="canonical" href="{html.escape(canonical)}">
<link rel="icon" type="image/png" href="{base_url}/logo.png">
<meta property="og:type" content="article">
<meta property="og:title" content="{html.escape(label)} detection use cases — Clankerusecase">
<meta property="og:description" content="{html.escape(meta_desc)}">
<meta property="og:url" content="{html.escape(canonical)}">
<meta property="og:image" content="{base_url}/logo.png">
<meta property="og:site_name" content="Clankerusecase">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{html.escape(label)} detections">
<meta name="twitter:description" content="{html.escape(meta_desc)}">
<script type="application/ld+json">
{{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "{html.escape(label)} detection use cases",
  "description": "{html.escape(meta_desc)}",
  "url": "{canonical}",
  "publisher": {{ "@type": "Organization", "name": "Clankerusecase",
                  "url": "{base_url}/" }}
}}
</script>
<style>{_TECH_PAGE_STYLE}</style>
</head>
<body>
<header class="tp">
  <a href="{base_url}/" class="brand">
    <img src="{base_url}/logo.png" alt="">
    <div>Clankerusecase<div class="sub">{html.escape(label)} detection coverage</div></div>
  </a>
  <a href="{base_url}/" class="back">← Back to main site</a>
</header>
<main>
  <div class="crumb">
    <a href="{base_url}/">Home</a><span class="sep">/</span>
    Targets<span class="sep">/</span>
    {html.escape(label)}
  </div>
  <h1 class="title"><span class="tid">{html.escape(icon or "")}</span>{html.escape(label)} detections</h1>
  <p class="lead">{lead}</p>
  <p class="lead" style="opacity:.85">{html.escape(blurb)}</p>
  <div class="cta">
    <a class="primary" href="{base_url}/#tab-library?target={html.escape(tag)}">Open Detection Library →</a>
    <a href="{base_url}/#tab-attack-matrix">View on the matrix</a>
  </div>
  <div class="stats">
    <div class="stat"><span class="n">{n_ucs}</span><span class="l">Use cases</span></div>
    <div class="stat"><span class="n">{n_techs}</span><span class="l">Techniques</span></div>
    <div class="stat"><span class="n">{n_arts}</span><span class="l">Articles</span></div>
    <div class="stat"><span class="n">{len([p for p in by_phase if by_phase[p]])}</span><span class="l">Kill-chain phases</span></div>
  </div>
  {tech_html}
  {"".join(phase_blocks)}
  {arts_html}
</main>
<footer>
  Auto-generated from the Clankerusecase use-case catalogue. Re-built every 2 hours.
</footer>
</body>
</html>
"""


def write_target_pages(matrix_data: dict,
                        base_url: str = "https://clankerusecase.com") -> int:
    """Emit one static HTML page per target surface under targets/.
    Returns the count written. Wipes the directory first so deletes
    propagate when targets rotate out of the corpus."""
    if not matrix_data:
        return 0
    out_dir = Path(__file__).parent / "targets"
    if out_dir.exists():
        import shutil
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for tag, label, icon, blurb in TARGET_DISPLAY:
        try:
            page = _render_target_page(tag, label, icon, blurb, matrix_data, base_url)
            (out_dir / f"{tag}.html").write_text(page, encoding="utf-8")
            written += 1
        except (OSError, KeyError) as e:
            print(f"    [!] target page failed for {tag}: {str(e)[:80]}")
    print(f"[*] Target landing pages: {written}  ->  targets/")
    return written


def write_briefings(articles_meta, articles_raw_index):
    BRIEFINGS_DIR.mkdir(exist_ok=True)
    written = []
    skipped_curated = 0
    for am in articles_meta:
        a = articles_raw_index.get(am["id"])
        if not a:
            continue
        a["sev"] = am.get("sev", "low")
        a["sources"] = am.get("sources") or [a.get("source", "")]
        ind = am.get("ind") or {}
        pub = am.get("published") or "undated"
        day_dir = BRIEFINGS_DIR / (pub if re.match(r"^\d{4}-\d{2}-\d{2}$", pub) else "undated")
        day_dir.mkdir(parents=True, exist_ok=True)
        slug = _slug(am["title"])
        path = day_dir / f"{slug}.md"

        # If the briefing exists and is marked curated by an analyst, leave it alone.
        if path.exists():
            try:
                head = path.read_text(encoding="utf-8")[:500]
                if CURATED_MARKER in head:
                    skipped_curated += 1
                    written.append(path)
                    continue
            except Exception:
                pass

        if (am.get("sources") or [a.get("source", "")])[0] == "CISA KEV":
            md = _kev_briefing(a, ind, [u for _, u in am.get("ucs", [])])
        else:
            ucs_pairs = am.get("ucs", []) or []
            techs = []
            for _uc_var, uc in ucs_pairs:
                for tid, tname in uc.techniques:
                    if (tid, tname) not in techs:
                        techs.append((tid, tname))
            md = _news_briefing(a, ind, ucs_pairs, techs, set(), am.get("sev", "low"))
        path.write_text(md, encoding="utf-8")
        written.append(path)

    # Stale-briefing cleanup. The pipeline only WRITES briefings for the
    # current article set — anything left behind from a previous run (e.g.
    # the four 2026-05-12 TanStack briefings that survived from before the
    # canonical-ID dedupe shipped) becomes an orphan. Walk the directory
    # and delete .md files we didn't write this run, but skip the special
    # roots (INDEX.md, _TEMPLATES.md) and any CURATED_MARKER-tagged files.
    kept = {p.resolve() for p in written}
    stale_removed = 0
    SPECIAL_NAMES = {"INDEX.md", "_TEMPLATES.md"}
    for existing_path in BRIEFINGS_DIR.rglob("*.md"):
        if existing_path.name in SPECIAL_NAMES:
            continue
        if existing_path.resolve() in kept:
            continue
        try:
            head = existing_path.read_text(encoding="utf-8")[:500]
            if CURATED_MARKER in head:
                continue
        except Exception:
            pass
        try:
            existing_path.unlink()
            stale_removed += 1
        except OSError:
            pass
    if stale_removed:
        print(f"    [*] Removed {stale_removed} stale briefing(s) from prior runs")

    idx_lines = [
        "# Briefings — full archive\n",
        f"_{len(written)} per-article briefings — auto-generated from every article we've pulled. Articles never age off; the corpus only grows._\n",
        "",
        "**Shared detection templates:** generic IOC-substitution hunts ",
        "(asset exposure, network IOC, hash IOC) live once in [`_TEMPLATES.md`](./_TEMPLATES.md) ",
        "instead of being repeated on every briefing. Each briefing links to the relevant template.",
        "",
    ]
    by_day = {}
    for p in written:
        by_day.setdefault(p.parent.name, []).append(p)
    for day in sorted(by_day.keys(), reverse=True):
        idx_lines.append(f"\n## {day}")
        for p in sorted(by_day[day]):
            idx_lines.append(f"- [{p.stem.replace('-', ' ')}](./{day}/{p.name})")
    (BRIEFINGS_DIR / "INDEX.md").write_text("\n".join(idx_lines), encoding="utf-8")
    _write_briefing_templates()
    if skipped_curated:
        print(f"    {skipped_curated} curated briefings preserved (analyst-edited)")
    return written


# =============================================================================
# Main
# =============================================================================

def _parse_published(entry):
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            return dt.datetime(*entry.published_parsed[:6], tzinfo=dt.timezone.utc)
        except Exception:
            pass
    s = entry.get("published") or entry.get("updated") or ""
    if not s:
        return None
    try:
        from email.utils import parsedate_to_datetime
        d = parsedate_to_datetime(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d
    except Exception:
        return None


# --- Full article body fetching (so IOC extraction sees more than the RSS preview) ---
ARTICLE_CACHE_DIR = Path(__file__).parent / "intel" / ".article_cache"
FETCH_FULL_BODY = os.environ.get("THN_FETCH_FULL_BODY", "1") not in ("0", "false", "no", "")
FETCH_DELAY_SEC = float(os.environ.get("THN_FETCH_DELAY", "1.2"))
FETCH_TIMEOUT_SEC = 25
FETCH_USER_AGENT = (
    "Mozilla/5.0 (compatible; usecaseintel-bot/1.0; "
    "+https://github.com/Virtualhaggis/usecaseintel) IOC-extractor"
)

# Tags whose content is noise for IOC extraction. Stripped before regex matching.
_NOISE_TAG_RE = re.compile(
    r"<(script|style|nav|header|footer|aside|form|button|svg|noscript)\b[^>]*>"
    r".*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
# Inline elements / class hints that frame ads, comments, related-stories blocks.
_NOISE_BLOCK_RE = re.compile(
    r"<(div|section|aside)\b[^>]*"
    r"class=\"[^\"]*"
    r"(comment|related|advert|sidebar|share|social|newsletter|subscribe|popup|modal|cookie)"
    r"[^\"]*\"[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)


def _cache_path_for(url: str) -> Path:
    h = hashlib.sha1(url.encode("utf-8", errors="replace")).hexdigest()
    return ARTICLE_CACHE_DIR / f"{h[:2]}" / f"{h}.html"


def _extract_main_html(html_doc: str) -> str:
    """Find the most-likely article-body region.

    Heuristic order — pick the LONGEST candidate above the threshold so
    sites that wrap only their header in <article> (Microsoft Security
    Blog) don't lose the body. Falls through to the whole doc if no
    container is large enough — IOC extraction is conservative anyway
    (regex-only or defanged-only), so noise tolerance is acceptable.
    """
    if not html_doc:
        return ""
    THRESHOLD = 2000
    candidates = []
    # 1. <article> tags — collect ALL, not just first.
    for m in re.finditer(r"<article\b[^>]*>(.*?)</article>", html_doc, re.IGNORECASE | re.DOTALL):
        candidates.append(m.group(1))
    # 2. common article-body class / id hints (THN, BC, Microsoft, etc.)
    body_class_re = re.compile(
        r"<(div|section|main)\b[^>]*"
        r"(?:class|id)=\"[^\"]*"
        r"(post-body|entry-content|articleBody|article-body|article__body|post__content|"
        r"post-content|article-content|story-content|content-body|articletext|"
        r"single-article|single-post|main-content|story-body|c-richtext|"
        r"rich-text|blog-post-content|wp-block-post-content)"
        r"[^\"]*\"[^>]*>(.*?)</\1>",
        re.IGNORECASE | re.DOTALL,
    )
    for m in body_class_re.finditer(html_doc):
        candidates.append(m.group(3))
    # 3. <main>
    m = re.search(r"<main\b[^>]*>(.*?)</main>", html_doc, re.IGNORECASE | re.DOTALL)
    if m:
        candidates.append(m.group(1))
    # Pick the longest candidate above threshold; otherwise fall back to whole doc.
    candidates = [c for c in candidates if len(c) > THRESHOLD]
    if candidates:
        return max(candidates, key=len)
    return html_doc


def _html_to_text_for_iocs(html_doc: str) -> str:
    """Convert article HTML to plain text suitable for IOC extraction.

    Preserves the textual content of <code>, <pre>, and table cells (where
    hashes / IPs / domains typically live in vendor write-ups) and strips
    obvious noise tags first.
    """
    if not html_doc:
        return ""
    body = _extract_main_html(html_doc)
    body = _NOISE_TAG_RE.sub(" ", body)
    body = _NOISE_BLOCK_RE.sub(" ", body)
    # <br> and </p> -> newline so multi-line IOCs aren't merged into one giant blob
    body = re.sub(r"<br\s*/?>", "\n", body, flags=re.IGNORECASE)
    body = re.sub(r"</p>", "\n", body, flags=re.IGNORECASE)
    body = re.sub(r"</li>", "\n", body, flags=re.IGNORECASE)
    body = re.sub(r"</tr>", "\n", body, flags=re.IGNORECASE)
    body = strip_html(body)
    body = html.unescape(body)
    body = re.sub(r"[ \t]+", " ", body)
    body = re.sub(r"\n[ \n]+", "\n", body)
    return body.strip()


def _extract_article_image_urls(html_doc: str, base_url: str, max_images: int = 5) -> list:
    """Pull the <img src> URLs out of the article body, filter junk
    (logos, avatars, tracking pixels, sprites, share-button icons), and
    return up to `max_images` absolute URLs in document order.

    Threat-intel articles routinely embed:
      - command-line / payload screenshots (literal IOC strings),
      - process-tree diagrams,
      - phishing-page decoys,
      - C2 panel screenshots,
      - flowcharts of multi-stage chains.

    Pure HTML→text strip drops all of these, which is why the LLM
    needs a list of URLs it can fetch through WebFetch when it
    suspects an image carries detection-grade content."""
    from urllib.parse import urljoin
    if not html_doc:
        return []
    main = _extract_main_html(html_doc)
    raw = re.findall(r'<img\b[^>]+?src=["\']([^"\']+)["\']', main, re.IGNORECASE)
    # Reject patterns common for chrome / social / tracking / ads.
    REJECT = (
        "/avatar", "gravatar.com", "/logo", "/icon", "/sprite", "/ads/",
        "/advert", "doubleclick.net", "googlesyndication", "google-analytics",
        "facebook.com/tr", "linkedin.com/li", "twitter.com/i/", "x.com/i/",
        "/share-button", "/social/", "/badge", "/emoji",
        "1x1.gif", "pixel.gif", "spacer.gif", "blank.gif",
    )
    out = []
    seen = set()
    for src in raw:
        src = src.strip()
        if not src:
            continue
        if src.startswith("data:"):
            continue
        # Resolve relative paths against the article URL.
        absolute = urljoin(base_url, src)
        if not absolute.lower().startswith(("http://", "https://")):
            continue
        low = absolute.lower()
        if any(p in low for p in REJECT):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        out.append(absolute)
        if len(out) >= max_images:
            break
    return out


def _fetch_full_body(url: str, fallback: str = "") -> tuple:
    """Fetch and clean an article body. Cached to disk; falls back on error.

    Returns a (text, image_urls) tuple. `image_urls` is a list of up to
    five content-image URLs harvested from the article HTML — they're
    forwarded to the LLM so it can WebFetch and analyse screenshots /
    flow diagrams / IOC-tables-as-images that pure text strip misses.
    """
    if not FETCH_FULL_BODY or not url or not url.lower().startswith(("http://", "https://")):
        return (fallback, [])
    cache = _cache_path_for(url)
    html_doc = ""
    if cache.exists():
        try:
            html_doc = cache.read_text(encoding="utf-8", errors="replace")
        except Exception:
            html_doc = ""
    if not html_doc:
        try:
            import requests
            time.sleep(FETCH_DELAY_SEC)
            r = requests.get(
                url,
                headers={"User-Agent": FETCH_USER_AGENT, "Accept": "text/html,*/*"},
                timeout=FETCH_TIMEOUT_SEC,
                allow_redirects=True,
            )
            if r.status_code == 200 and r.text:
                html_doc = r.text
                cache.parent.mkdir(parents=True, exist_ok=True)
                try:
                    cache.write_text(html_doc, encoding="utf-8", errors="replace")
                except Exception:
                    pass
            else:
                return (fallback, [])
        except Exception as e:
            safe_err = str(e).encode("ascii", "replace").decode("ascii")
            print(f"    [!] body fetch failed for {url[:80]}: {safe_err}")
            return (fallback, [])
    text = _html_to_text_for_iocs(html_doc)
    if len(text) < 200:
        # extraction looks broken — better to keep the RSS summary than ship rubbish
        return (fallback, [])
    images = _extract_article_image_urls(html_doc, url)
    return (text, images)


def _fetch_rss(source, since):
    feed = feedparser.parse(source["url"])
    out = []
    fetched = 0
    for e in feed.entries[:MAX_PER_SOURCE]:
        pub = _parse_published(e)
        if since and pub and pub < since:
            continue
        rss_summary = strip_html(e.get("summary", "") or e.get("description", "") or "")
        rss_summary = re.sub(r"\s+", " ", rss_summary).strip()
        link = e.get("link", "")

        # Pull the full article body so IOC extraction sees hashes / defanged
        # IPs / domains that live below the RSS preview. Also harvest the
        # in-article image URLs — they get forwarded to the LLM so it can
        # WebFetch screenshots / flow diagrams that pure text strip misses.
        full_body, image_urls = _fetch_full_body(link, fallback=rss_summary)
        if full_body and full_body != rss_summary:
            fetched += 1

        out.append({
            "source": source["name"],
            "title": e.get("title", "(untitled)").strip(),
            "link": link,
            "published": e.get("published", ""),
            "published_dt": pub,
            # Display preview stays short; raw_body holds full text for IOC extraction.
            "summary": (rss_summary[:600] + "…") if len(rss_summary) > 600 else rss_summary,
            "raw_body": full_body or rss_summary,
            "image_urls": image_urls,
        })
    if fetched:
        print(f"    -> fetched {fetched} full article bodies")
    return out


def _fetch_ghsa(source, since):
    """Pull reviewed advisories from the GitHub Security Advisories REST API
    and shape them like RSS articles so the rest of the pipeline can treat
    them uniformly. The atom endpoint (github.com/advisories.atom) is gated
    server-side and returns 406 to non-pjax requests; api.github.com/advisories
    is the supported public path.

    Each advisory becomes one article with a body composed of the advisory
    summary + description + affected-package list. Package coordinates like
    "@tanstack/react-router @ < 1.95.4" land in raw_body so downstream IOC
    extraction can pick them up alongside any embedded hashes / CVEs.
    """
    import urllib.request as _ur
    req = _ur.Request(source["url"],
                      headers={"User-Agent": "Mozilla/5.0 (compatible; thn-usecases/1.0)",
                               "Accept": "application/vnd.github+json",
                               "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with _ur.urlopen(req, timeout=30) as r:
            advisories = __import__("json").loads(r.read())
    except Exception as e:
        print(f"    [!] GHSA fetch failed: {e}")
        return []
    out = []
    # GHSA is Critical-only now. High / Medium / Low are routine vendor
    # patch advisories that drown the Articles feed without earning their
    # place — analysts asked us to keep them out entirely. The feed is
    # still polled so canonical-ID dedupe can use GHSA entries to merge
    # cross-vendor coverage when a CVE matches a news article.
    for a in advisories or []:
        pub_iso = a.get("published_at") or a.get("updated_at") or ""
        try:
            pub = dt.datetime.fromisoformat(pub_iso.replace("Z", "+00:00"))
        except Exception:
            pub = None
        if since and pub and pub < since:
            continue
        if len(out) >= MAX_PER_SOURCE:
            break
        ghsa_id  = a.get("ghsa_id") or ""
        cve_id   = a.get("cve_id") or ""
        severity = (a.get("severity") or "unknown").lower()
        summary  = (a.get("summary") or "").strip()
        # Package coordinates list — primary content for supply-chain UCs.
        pkg_bits = []
        for v in (a.get("vulnerabilities") or []):
            pkg  = v.get("package") or {}
            eco  = pkg.get("ecosystem") or ""
            name = pkg.get("name") or ""
            rng  = v.get("vulnerable_version_range") or ""
            pf   = v.get("patched_versions") or ""
            if name:
                seg = f"{eco}:{name}" if eco else name
                if rng: seg += f" (vuln {rng})"
                if pf:  seg += f" — patched {pf}"
                pkg_bits.append(seg)
        # Drop everything that isn't Critical. The advisory still exists
        # in the GHSA feed and could be re-enabled later; we just don't
        # publish a card for it.
        if severity != "critical":
            continue
        body_parts = [summary, a.get("description") or ""]
        if pkg_bits:
            body_parts.append("Affected packages: " + "; ".join(pkg_bits[:40]) + ".")
        if cve_id:
            body_parts.append(f"Tracked as {cve_id}.")
        body = "\n\n".join(p for p in body_parts if p).strip()
        title_id = cve_id or ghsa_id
        title = f"[GHSA / {severity.upper()}] {title_id}: {summary[:160]}" if summary else f"[GHSA / {severity.upper()}] {title_id}"
        out.append({
            "source":       "GitHub Security Advisories",
            "title":        title,
            "link":         a.get("html_url") or f"https://github.com/advisories/{ghsa_id}",
            "published":    pub_iso,
            "published_dt": pub,
            "summary":      summary,
            "raw_body":     body,
            "image_urls":   [],
        })
    return out


def _fetch_kev(source, since):
    import urllib.request as _ur
    req = _ur.Request(source["url"],
                      headers={"User-Agent": "Mozilla/5.0 (compatible; thn-usecases/1.0)"})
    try:
        with _ur.urlopen(req, timeout=30) as r:
            data = __import__("json").loads(r.read())
    except Exception as e:
        print(f"    [!] CISA KEV fetch failed: {e}")
        return []
    out = []
    for v in data.get("vulnerabilities", []):
        date_added = v.get("dateAdded", "")
        try:
            pub = dt.datetime.fromisoformat(date_added).replace(tzinfo=dt.timezone.utc)
        except Exception:
            pub = None
        if since and pub and pub < since:
            continue
        if len(out) >= MAX_PER_SOURCE:
            break
        cve = v.get("cveID", "") or ""
        vname = v.get("vulnerabilityName", "") or ""
        vendor = v.get("vendorProject", "") or ""
        product = v.get("product", "") or ""
        title = f"CISA KEV: {cve} — {vname}" if vname else f"CISA KEV: {cve}"
        bits = []
        if v.get("shortDescription"):
            bits.append(v["shortDescription"])
        if vendor or product:
            bits.append(f"Vendor: {vendor}, Product: {product}.")
        if v.get("knownRansomwareCampaignUse") and v["knownRansomwareCampaignUse"].lower() != "unknown":
            bits.append(f"Known ransomware use: {v['knownRansomwareCampaignUse']}.")
        if v.get("dueDate"):
            bits.append(f"Federal patch due: {v['dueDate']}.")
        body = " ".join(bits)
        out.append({
            "source": "CISA KEV",
            "title": title,
            "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published": date_added,
            "published_dt": pub,
            "summary": body,
            "raw_body": body + " " + cve,
            "image_urls": [],
        })
    return out


_DEDUPE_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "in", "on", "to", "for", "with",
    "by", "as", "at", "from", "is", "was", "be", "been", "are", "this", "that",
    "after", "over", "via", "new", "amid", "into", "out", "up", "than",
}

def _title_tokens(title: str):
    """Lowercase, alphanumeric-only token set, minus stopwords + 1-char fragments."""
    return {t for t in re.findall(r"[a-z0-9]+", title.lower())
            if t not in _DEDUPE_STOPWORDS and len(t) > 1}


# High-precision tags that identify a specific incident regardless of phrasing.
# When two articles share any of these in their title+body, they're the same
# story even if the title-token Jaccard is well below the 0.55 threshold —
# different vendors describe the same incident with wildly different titles
# (e.g. "84 TanStack npm Packages Hacked..." vs "Mini Shai-Hulud Is Back...").
# Keep this list short, high-signal, and only add when a campaign starts
# generating cross-vendor coverage that the token-overlap rule misses.
_NAMED_INCIDENT_TAGS = (
    "shai-hulud", "mini shai-hulud", "shai hulud",
    "teampcp", "team-pcp",
    "lazarus", "bluenoroff",
    "scattered spider", "scattered-spider", "muddled libra",
    "lumma stealer", "redline stealer", "stealc",
    "clickfix",
)
_CVE_RE  = re.compile(r"\b(cve-\d{4}-\d{4,7})\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\b(ghsa-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.IGNORECASE)
_PKG_RE  = re.compile(r"(@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9_-]*)", re.IGNORECASE)
# Bare project-name detector: catches phrases like "TanStack npm packages"
# or "Mistral PyPI package" or "lodash crate". These are typically the
# compromised project's name, mentioned without the @scope/name form.
# Five vendors covering the same compromised npm project will all have
# this pattern in their title — so they collapse correctly. Restricted
# to ecosystem keywords (npm/pypi/gem/...) so it doesn't grab random
# capitalised words.
_BARE_PROJ_RE = re.compile(
    r"\b([a-z][a-z0-9._-]{2,40})\s+(?:npm|pypi|composer|gem|crate|nuget|rubygem)s?\b",
    re.IGNORECASE,
)
_BARE_PROJ_BLOCKLIST = {
    # Ecosystem keywords / generic words that shouldn't become project tags.
    "the", "a", "an", "this", "that", "these", "those", "all", "some",
    "multiple", "many", "several", "various", "new", "fake", "malicious",
    "trojanized", "trojanised", "compromised", "vulnerable", "affected",
    "popular", "official", "open-source", "open", "source", "private",
    "public", "any", "every", "another",
}

def _canonical_ids(article: dict) -> set:
    """Pull high-precision identifiers from title + summary + body. Used by
    the same-story dedupe pass alongside title-token Jaccard.

    Returns a set of normalised lowercase tags. Empty set means "no anchor
    identifiers found" — fall back to Jaccard only."""
    text = " ".join([
        (article.get("title") or ""),
        (article.get("summary") or ""),
        (article.get("raw_body") or "")[:4000],  # body cap — first 4 KB is plenty
    ]).lower()
    ids = set()
    ids.update(m.group(1).lower() for m in _CVE_RE.finditer(text))
    ids.update(m.group(1).lower() for m in _GHSA_RE.finditer(text))
    for m in _PKG_RE.finditer(text):
        coord = m.group(1).lower()
        ids.add(coord)
        # Bridge: also emit a proj:<scope> tag so an article that only
        # mentioned "@tanstack/react-router" merges with one that says
        # "TanStack npm packages" (which yields proj:tanstack via the
        # bare-project regex below). Without this bridge the CSN article
        # was orphaned from the rest of the TanStack / Shai-Hulud cluster.
        scope = coord.split("/", 1)[0].lstrip("@")
        if scope and len(scope) >= 3:
            ids.add(f"proj:{scope}")
    for tag in _NAMED_INCIDENT_TAGS:
        if tag in text:
            # Normalise spaces vs hyphens so "Mini Shai-Hulud" and
            # "Mini Shai Hulud" collapse together.
            ids.add(tag.replace(" ", "-"))
    # Bare project-name extraction — only from the title (high precision).
    # Five vendors all saying "TanStack npm packages" / "Mistral PyPI" all
    # land the same proj:tanstack / proj:mistral tag. Body usage is too
    # noisy (every "use npm install" mention would match).
    title = (article.get("title") or "").lower()
    for m in _BARE_PROJ_RE.finditer(title):
        proj = m.group(1).lower().strip("._-")
        if proj and proj not in _BARE_PROJ_BLOCKLIST and len(proj) >= 3:
            ids.add(f"proj:{proj}")
    return ids


def _looks_same_story(a, b, threshold=0.55):
    """Jaccard similarity of significant title tokens."""
    if not a or not b:
        return False
    inter = a & b
    if not inter:
        return False
    union = a | b
    return (len(inter) / len(union)) >= threshold


_MARKETING_TITLE_STARTS = (
    "introducing ", "announcing ", "we've launched", "we have launched",
    "we're excited", "we are excited", "we're thrilled", "we are thrilled",
    "we're pleased to", "now in beta", "now in ga", "now available",
    "now generally available", "today we're", "today we are",
    "new from ", "from the team at ",
)
_MARKETING_TITLE_CONTAINS = (
    " now integrates with ", " integrates with ", " partners with ",
    " bridging the gap ",
    # Webinar / event noise — extends the existing LLM-gate stopwords to the
    # accept-article gate so they never even appear on the site.
    "webinar:", "webinar -", "podcast:", " podcast ",
    "join us at ", "join us for ", "live demo:",
)
# Strong-signal threat content words. If any of these are present the article
# is allowed through even when a marketing pattern matches — e.g. "Introducing
# StepSecurity's TeamPCP findings" should NOT be blocked.
_OVERRIDE_KEYWORDS = (
    "cve-", "0-day", "zero-day", "exploit", "malware", "ransomware",
    "trojan", "stealer", "backdoor", "intrusion", "compromise",
    "supply chain", "supply-chain", "campaign", "actor", "shai-hulud",
    "in the wild", "actively exploited", "active exploit",
)
def _is_marketing_post(article: dict) -> bool:
    """Reject obvious vendor product-marketing / event-announcement posts at
    the fetch boundary so they never bloat the site. We err on the side of
    keeping content when in doubt — the override-keyword check above protects
    titles that LOOK promotional but actually carry threat intel."""
    title = (article.get("title") or "").lower()
    if not title:
        return False
    if any(kw in title for kw in _OVERRIDE_KEYWORDS):
        return False
    if any(title.startswith(p) for p in _MARKETING_TITLE_STARTS):
        return True
    if any(p in title for p in _MARKETING_TITLE_CONTAINS):
        return True
    return False


# =============================================================================
# Relevance classifier — three-tier gate that decides whether each article
# becomes a card on the Articles tab. Output is binary (alert | drop) but the
# internal tiers are observable so we can audit why something was dropped.
#
#   Tier 0: strong-keep override (active threat signal OR security-estate)
#   Tier 1: strong-drop regex (listicle / opinion / OS feature launch / etc.)
#   Tier 2: cached LLM call on Haiku for ambiguous middle-ground items
#
# Tier 0 wins; Tier 2 is only reached if neither 0 nor 1 fired. Failure of any
# tier defaults to ALERT — we never silently drop on infrastructure errors.
# =============================================================================

# Security products the SOC / security-engineering team operates. An article
# that mentions one of these in its title or lead paragraph is operationally
# relevant even if it reads like a product launch ("CrowdStrike Falcon 7.21
# Released" still matters — the team running Falcon needs to know).
_SECURITY_ESTATE_KEYWORDS = (
    # EDR / antivirus
    "defender", "microsoft defender", "windows defender", "defender for endpoint",
    "defender for cloud", "defender atp", "sentinelone", "singularity",
    "crowdstrike", "falcon", "cortex xdr", "carbon black", "vmware carbon black",
    "trellix", "fireeye", "symantec", "kaspersky", "eset", "bitdefender",
    "sophos", "trend micro", "elastic security", "elastic edr", "tanium",
    # SIEM / detection platforms
    "splunk", "microsoft sentinel", "azure sentinel", "qradar", "logrhythm",
    "exabeam", "sumologic", "sumo logic", "datadog cloud siem", "chronicle",
    "google secops", "google security operations", "panther",
    # Firewall / network security
    "palo alto", "fortinet", "fortigate", "fortianalyzer", "check point",
    "cisco firepower", "cisco asa", "cisco secure", "juniper srx", "panos",
    "zscaler", "netskope",
    # Identity / IAM
    "okta", "duo security", "ping identity", "azure ad", "entra id",
    "active directory", "cyberark", "beyondtrust",
    # Cloud security / supply chain tooling
    "wiz", "lacework", "prisma cloud", "aqua security", "snyk", "veracode",
    "kibana", "elastalert", "graylog",
    # MITRE / detection tooling
    "atomic red team", "caldera", "sigma rules",
)

# Hard-drop regex patterns applied to titles. Each row drops a class of
# content analysts have asked us NOT to render. Tier-0 override fires before
# this so KEV / IOCs / actors / security-estate articles slip past unharmed.
_RELEVANCE_DROP_PATTERNS = (
    re.compile(r"^\s*(\d+\s+(best|top|worst)\b|top\s+\d+\b)", re.I),
    re.compile(r"^(state of |year in |one year of |looking back|"
               r"what we (built|learned)|what['’]s next)", re.I),
    # Opinion lead-ins. Allow up to 5 words after "Why" so it catches multi-
    # word subjects like "Why Agentic AI Is Security's Next Blind Spot".
    re.compile(r"^why\s+\S+(?:\s+\S+){0,5}\s+(is|are|will|won['’]?t|isn['’]?t)\b", re.I),
    re.compile(r"^(is\s+\w+\s+the\s+next|the\s+case\s+for)\b", re.I),
    re.compile(r"\bis\s+(dead|back|broken|over|a\s+fear\s+response)\b", re.I),
    re.compile(r"\b(next\s+blind\s+spot|fear\s+response|hot\s+take)\b", re.I),
    re.compile(r"^(how to|a beginner|step.by.step|getting started|what is)", re.I),
    # Generic consumer / OS feature-launch with no attack vocab. Allows up
    # to 3 words between the verb and the feature noun ("iOS 26.5 Brings
    # Default End-to-End Encrypted RCS Messaging…"). Tier-0 override list
    # already excludes actively-exploited language.
    re.compile(r"\b(brings|launches|introduces|unveils|adds|enhances|"
               r"rolls\s+out)\b(?:\s+\S+){0,3}\s+"
               r"(end-to-end|encryption|messaging|protections?|privacy|"
               r"banking\s+scam|consent|onboarding|rcs)", re.I),
)

# Analyst escape hatch — title-substring matches here ALWAYS keep, even if
# a Tier-1 pattern would otherwise drop. Append to this if the classifier
# false-positively drops something real. No cache clear needed; this runs
# before the Tier-2 cache lookup.
_RELEVANCE_OVERRIDE_TITLES = (
    # Add lowercase substrings here, e.g. "specific incident name"
)

# Active-threat keywords that move an article straight into ALERT when
# paired with a CVE in the body — these are the words vendors use when
# something is being exploited rather than just patched.
_EXPLOITATION_KEYWORDS = (
    "actively exploited", "active exploitation", "exploited in the wild",
    "in the wild", "0-day", "zero-day", "zero day", "weaponized",
    "weaponised", "exploit chain", "under active attack", "exploitation observed",
)


def _strong_keep_signal(article: dict, ind: dict) -> str | None:
    """Tier 0. Return a short reason string if the article must be kept,
    else None. Checked before any drop logic."""
    title = (article.get("title") or "").lower()
    body  = (article.get("raw_body") or "").lower()
    head  = title + " " + body[:500]

    # Analyst-supplied override
    for sub in _RELEVANCE_OVERRIDE_TITLES:
        if sub.lower() in title:
            return "override-allowlist"

    sources = article.get("sources") or [article.get("source", "")]
    if "CISA KEV" in sources:
        return "kev-cited"

    # CVEs present AND exploitation language
    if ind and ind.get("cves"):
        if any(kw in head for kw in _EXPLOITATION_KEYWORDS):
            return "cve+exploitation"

    # Hard IOCs extracted from the article body
    if ind and (ind.get("hashes") or ind.get("sha256") or ind.get("sha1")
                or ind.get("md5") or ind.get("ips") or ind.get("domains")):
        return "iocs-present"

    # Named threat actor detected by the existing actor matcher
    if article.get("_actors"):
        return "named-actor"

    # Canonical-ID set (built during dedupe) contains a named campaign or
    # @scope/pkg coordinate.
    ids = article.get("_ids") or set()
    for tag in ids:
        if isinstance(tag, str) and (tag.startswith("@") or tag.startswith("proj:")
                                     or tag in _NAMED_INCIDENT_TAGS
                                     or tag.replace(" ", "-") in _NAMED_INCIDENT_TAGS):
            return "campaign-or-package"

    # Security-estate impact — analyst must react when their tooling changes
    for kw in _SECURITY_ESTATE_KEYWORDS:
        if kw in head:
            return f"security-estate:{kw[:24]}"

    return None


def _relevance_drop_pattern(article: dict) -> str | None:
    """Tier 1. Return the matching regex source if the title fires a hard-
    drop pattern, else None."""
    title = (article.get("title") or "")
    if not title:
        return None
    for rx in _RELEVANCE_DROP_PATTERNS:
        if rx.search(title):
            return rx.pattern[:60]
    return None


_RELEVANCE_PROMPT = (
    "Title: <<TITLE>>\n"
    "Body excerpt (first 1500 chars): <<BODY>>\n\n"
    "You are a SOC analyst / security engineer triaging a threat-intel feed.\n"
    "ALERT if the article describes any of:\n"
    "  - an active campaign, breach, IOC release, named threat actor,\n"
    "    detectable attack technique\n"
    "  - a CVE that is actively exploited in the wild\n"
    "  - a patch / regression / bypass / feature change to a security product\n"
    "    (EDR, SIEM, firewall, IAM) that the operations team must react to\n"
    "DROP if it is a listicle, generic product launch, opinion piece, year-in-\n"
    "review, vendor retrospective, generic tutorial, or general tech news\n"
    "with no attack content and no impact on the security estate.\n\n"
    "Reply ONLY with one line of JSON, no prose, no code fences:\n"
    '{"class":"alert"|"drop","reason":"<=10 words"}'
)


def _llm_relevance_call(prompt: str) -> dict | None:
    """Cheap binary classifier — Haiku, max_tokens=120, no web search.
    Returns parsed dict or None on any failure (caller defaults to ALERT)."""
    use_oauth = os.environ.get("USECASEINTEL_USE_CLAUDE_OAUTH", "").lower() in ("1", "true", "yes")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    raw = None
    if use_oauth:
        try:
            from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock
            import asyncio
            async def _run():
                chunks = []
                opts = ClaudeAgentOptions(model=LLM_RELEVANCE_MODEL, max_turns=1, allowed_tools=[])
                async for msg in query(prompt=prompt, options=opts):
                    if isinstance(msg, AssistantMessage):
                        for block in msg.content:
                            if isinstance(block, TextBlock):
                                chunks.append(block.text)
                return "".join(chunks)
            raw = asyncio.run(_run())
        except Exception:
            raw = None
    if raw is None and api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model=LLM_RELEVANCE_MODEL,
                max_tokens=120,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = "".join(b.text for b in msg.content if hasattr(b, "text"))
        except Exception:
            raw = None
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```\s*$", "", raw)
    # Find first {..} object in the response.
    m = re.search(r"\{[^{}]*\}", raw, re.DOTALL)
    if not m:
        return None
    import json as _json
    try:
        d = _json.loads(m.group(0))
    except Exception:
        return None
    cls = (d.get("class") or "").strip().lower()
    if cls not in ("alert", "drop"):
        return None
    return {"class": cls, "reason": (d.get("reason") or "")[:120]}


def classify_relevance(article: dict, ind: dict, sev: str) -> tuple[str, str, str]:
    """Return (class, reason, tier) where class is 'alert' or 'drop'.

    Tier names: 'keep-0' (strong-keep override), 'drop-1' (regex hard drop),
    'llm-2-alert' / 'llm-2-drop' (LLM classifier), 'default-keep' (fallback).
    On LLM auth missing or any infra failure the function defaults to ALERT —
    we never silently drop on errors.
    """
    # Tier 0
    keep_reason = _strong_keep_signal(article, ind)
    if keep_reason:
        return ("alert", keep_reason, "keep-0")

    # Tier 1
    drop_pat = _relevance_drop_pattern(article)
    if drop_pat:
        return ("drop", f"matched: {drop_pat}", "drop-1")

    # Tier 2 — cached LLM
    url = article.get("link", "") or ""
    if not url:
        return ("alert", "no url, default keep", "default-keep")
    try:
        LLM_RELEVANCE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        key_input = f"{CLASSIFIER_VERSION}|{url}".encode("utf-8", "replace")
        cache_key = hashlib.sha1(key_input).hexdigest()
        cache_path = LLM_RELEVANCE_CACHE_DIR / f"{cache_key[:2]}/{cache_key}.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        if cache_path.exists():
            try:
                cached = __import__("json").loads(cache_path.read_text(encoding="utf-8"))
                if cached.get("class") in ("alert", "drop"):
                    return (cached["class"], cached.get("reason", "cached"),
                            f"llm-2-{cached['class']}")
            except Exception:
                pass
    except Exception:
        return ("alert", "cache init failed", "default-keep")

    body = (article.get("raw_body") or "")[:1500]
    prompt = (_RELEVANCE_PROMPT
              .replace("<<TITLE>>", (article.get("title") or "")[:300])
              .replace("<<BODY>>",  body))
    result = _llm_relevance_call(prompt)
    if not result:
        return ("alert", "llm unavailable", "default-keep")
    # Persist cache
    try:
        cache_path.write_text(__import__("json").dumps({
            "class":  result["class"],
            "reason": result["reason"],
            "version": CLASSIFIER_VERSION,
            "ts":     dt.datetime.now(dt.timezone.utc).isoformat(),
        }), encoding="utf-8")
    except Exception:
        pass
    return (result["class"], result["reason"], f"llm-2-{result['class']}")


def fetch_articles(limit: int = None, days: int = LOOKBACK_DAYS):
    """
    Pull articles from every configured source, filter to a rolling window
    of `days`, dedupe by normalised title (preserving multi-source attribution),
    and return newest first.
    """
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    print(f"[*] Lookback window: {days} days (since {since.strftime('%Y-%m-%d')})")
    raw = []
    for src in SOURCES:
        try:
            print(f"[*] {src['name']}…")
            if src["kind"] == "rss":
                items = _fetch_rss(src, since)
            elif src["kind"] == "kev":
                items = _fetch_kev(src, since)
            elif src["kind"] == "ghsa":
                items = _fetch_ghsa(src, since)
            else:
                items = []
        except Exception as e:
            safe_err = str(e).encode('ascii','replace').decode('ascii')
            print(f"    [!] failed: {safe_err}")
            items = []
        # Drop vendor product-marketing posts at the fetch boundary so they
        # never get cached, rendered, or LLM-processed. Logged so noisy
        # feeds become visible.
        before = len(items)
        items = [a for a in items if not _is_marketing_post(a)]
        dropped = before - len(items)
        if dropped:
            print(f"    -> dropped {dropped} marketing post(s)")
        print(f"    -> {len(items)} articles in window")
        raw.extend(items)

    # Pre-tokenize titles for word-set Jaccard dedupe across sources.
    # Also extract canonical incident IDs (CVE / GHSA / @scope/pkg / named
    # campaign / bare project name) — these are high-precision and let us
    # merge cross-vendor coverage that token-Jaccard would miss because
    # the titles barely overlap.
    for a in raw:
        a["_tokens"] = _title_tokens(a["title"])
        a["_ids"]    = _canonical_ids(a)

    # Merges only fire when articles are within this window of each other.
    # Stops cross-year campaign bleeds (e.g. original Shai-Hulud 2025-09
    # absorbing today's Mini Shai-Hulud coverage and backdating the card
    # to last September). 4h is tight on purpose — covers a normal news
    # cycle, not multi-wave campaigns.
    MERGE_WINDOW = dt.timedelta(hours=4)
    def _within_window(a_, b_):
        da, db = a_.get("published_dt"), b_.get("published_dt")
        if not da or not db:
            return True  # if either is undated, can't enforce — allow
        return abs(da - db) <= MERGE_WINDOW

    deduped = []
    same_story_merges = 0
    canonical_merges  = 0
    for a in raw:
        a["sources"] = [a["source"]]
        match = None
        for existing in deduped:
            if not _within_window(a, existing):
                continue
            # Existing rule: title-token Jaccard >= 0.55
            if _looks_same_story(a["_tokens"], existing["_tokens"]):
                match = existing; same_story_merges += 1
                break
            # New rule: any shared high-precision identifier counts as the
            # same incident regardless of how differently the two vendors
            # phrased the headline.
            shared_ids = a["_ids"] & existing["_ids"]
            if shared_ids:
                match = existing; canonical_merges += 1
                break
        if match:
            for s in a["sources"]:
                if s not in match["sources"]:
                    match["sources"].append(s)
            # Prefer the LATEST publication time — when 5 vendors cover the
            # same incident across a few hours, the analyst should see
            # "today" on the card, not the earliest source's timestamp.
            if (a.get("published_dt")
                and (not match.get("published_dt")
                     or a["published_dt"] > match["published_dt"])):
                match["published_dt"] = a["published_dt"]
                match["published"] = a["published"]
            # Prefer the longest summary
            if len(a.get("raw_body","")) > len(match.get("raw_body","")):
                match["summary"] = a["summary"]
                match["raw_body"] = a["raw_body"]
            # Carry forward canonical IDs from each merged article — every
            # subsequent comparison gets the full set, so a third article
            # sharing any one of them folds in too.
            match["_ids"] = match["_ids"] | a["_ids"]
            match["_tokens"] = match["_tokens"] | a["_tokens"]
        else:
            deduped.append(a)

    if canonical_merges:
        print(f"[*] Same-incident dedupe: merged {same_story_merges} by title-Jaccard, "
              f"{canonical_merges} by canonical-ID overlap (CVE / GHSA / package / named campaign)")

    # Normalise `published` for every survivor to ISO YYYY-MM-DD (UTC). Mixed
    # RFC-2822 vs ISO is exactly the kind of inconsistency that ends up in
    # downstream CSV/JSON exports and confuses analysts.
    for a in deduped:
        a.pop("_tokens", None)
        # Keep `_ids` on the article — the relevance classifier (Tier 0)
        # reads it to detect named-campaign / @scope-package coverage.
        if a.get("published_dt"):
            try:
                a["published"] = a["published_dt"].astimezone(dt.timezone.utc).strftime("%Y-%m-%d")
            except Exception:
                pass
    articles = deduped
    articles.sort(
        key=lambda a: a.get("published_dt") or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
        reverse=True,
    )
    print(f"[*] After dedupe: {len(articles)} unique articles ({len(raw) - len(articles)} duplicates merged)")
    if limit:
        articles = articles[:limit]
    return articles


def main():
    articles = fetch_articles()
    if not articles:
        sys.exit("[!] No articles returned from any source.")
    print(f"[*] {len(articles)} articles total. Building deep analysis…")

    # 24-hour re-review window: for any article published in the last day,
    # invalidate its cached LLM analysis if either (a) the body has been
    # edited since we cached, or (b) a similar article has appeared
    # elsewhere since. Forces a fresh LLM pass with the up-to-date inputs.
    try:
        _recent_window_revisit(articles, hours=24)
    except Exception as _e:
        print(f"[!] 24h re-review pre-pass failed: {_e}")

    cards = []
    nav_meta = []
    articles_meta = []
    total_ucs = 0
    total_techs = set()
    total_cves = set()
    sev_counts = {"crit":0,"high":0,"med":0,"low":0}
    # Relevance gate accounting
    relevance_tier_counts = {"keep-0": 0, "drop-1": 0, "llm-2-alert": 0,
                             "llm-2-drop": 0, "default-keep": 0}
    relevance_drop_log = []  # list of dicts -> intel/relevance_drops.jsonl

    # Need a stable mapping from UseCase object -> python variable name (so
    # the matrix can dedupe across articles that share the same UC instance).
    uc_var_map = {id(obj): name
                  for name in dir(__import__(__name__))
                  for obj in [getattr(__import__(__name__), name, None)]
                  if isinstance(obj, UseCase)}

    bespoke_built = 0
    actor_index = {}      # canonical actor name -> {articles:set, ucs:int, techs:set, ips:set, ...}
    for i, a in enumerate(articles):
        text = f"{a['title']}\n{a['raw_body']}"
        ind = extract_indicators(a["title"], a["raw_body"])
        techniques = infer_techniques(text, ind["explicit_ttps"])
        ucs = select_use_cases(text, ind)
        # Threat-actor extraction — case-insensitive substring match
        # against the curated alias list. Used to power the new Threat
        # Actors tab and a per-actor article filter.
        a["_actors"] = extract_threat_actors(a["title"], a["raw_body"])
        # Article-specific bespoke UC built from the actual mechanics named
        # in this article. Augments rather than replaces the rule-fired UCs:
        # the generic templates still cover the technique class; the bespoke
        # UC adds detection logic targeting THIS attack's specific binaries
        # and paths and command-line patterns. None when the article doesn't
        # contain enough mechanic detail (e.g. RSS-only stub, opinion piece).
        try:
            mechanics = extract_mechanics(a["title"], a["raw_body"])
            bespoke = _make_bespoke_uc(a["title"], mechanics, ind)
            if bespoke is not None:
                ucs.append(bespoke)
                bespoke_built += 1
                a["_bespoke_uc"] = bespoke
                a["_mechanics"] = mechanics
        except Exception as _e:
            print(f"    [!] bespoke UC failed for article {i}: {_e}")
        # LLM-driven bespoke UCs — opt-in via ANTHROPIC_API_KEY env var.
        # Reads the article and emits per-attack SPL/KQL targeting the
        # specific binaries / domains / chain described, qualitatively
        # better than regex extraction. Cached per article URL.
        try:
            llm_ucs = _llm_generate_ucs(a, ind)
            for u in llm_ucs:
                if u is None: continue
                ucs.append(u)
                bespoke_built += 1
        except Exception as _e:
            print(f"    [!] LLM UC failed for article {i}: {_e}")
        narrative_hit, _ = detect_kill_chain(text)
        hit = narrative_hit | {uc.kill_chain for uc in ucs}
        inferred = set()
        for ph in list(hit):
            inferred |= INFER_FROM_PHASE.get(ph, set())
        inferred -= hit
        sev = compute_severity(text, ind, ucs, techniques)
        # Relevance gate — decides whether this article gets a card on the
        # Articles tab. See `classify_relevance` for the three-tier rules.
        rel_class, rel_reason, rel_tier = classify_relevance(a, ind, sev)
        relevance_tier_counts[rel_tier] = relevance_tier_counts.get(rel_tier, 0) + 1
        if rel_class == "drop":
            relevance_drop_log.append({
                "id":     f"art-{i:02d}",
                "source": (a.get("sources") or [a.get("source", "?")])[0],
                "title":  a.get("title", ""),
                "tier":   rel_tier,
                "reason": rel_reason,
                "published": a.get("published", ""),
                "link":   a.get("link", ""),
            })
            # Drop quietly — article still contributed to IOC enrichment and
            # canonical-ID dedupe earlier in the pipeline.
            continue
        a["_relevance"] = rel_class
        a["_relevance_reason"] = rel_reason
        sev_counts[sev] += 1
        total_ucs += len(ucs)
        for tid, _ in techniques: total_techs.add(tid)
        for c in ind["cves"]: total_cves.add(c)
        cards.append(render_card(i, a, ind, techniques, hit, inferred, ucs, sev))
        nav_meta.append({"title": a["title"], "sev": sev})
        # For the matrix view: combine narrative-inferred techniques with the
        # techniques covered by any use case fired for this article. Otherwise
        # ~70% of articles look "uncovered" on the matrix purely because the
        # short RSS summary didn't trip the keyword-inference map.
        merged_techs = list(techniques)
        seen_t = {t for t, _ in techniques}
        for uc in ucs:
            for tid, tname in uc.techniques:
                if tid not in seen_t:
                    merged_techs.append((tid, tname))
                    seen_t.add(tid)
        # `published` was normalised to ISO YYYY-MM-DD by fetch_articles().
        articles_meta.append({
            "id": f"art-{i:02d}",
            "title": a["title"],
            "link": a["link"],
            "sev": sev,
            "sources": a.get("sources") or [a.get("source", "")],
            "published": a.get("published", ""),
            "techs": merged_techs,
            "ind": ind,
            "ucs": [(uc_var_map.get(id(uc), f"UC_{i}_{j}"), uc) for j, uc in enumerate(ucs)],
            "actors": a.get("_actors", []),
        })
        # Aggregate per-actor stats. Tracks: linked articles + dates,
        # use cases (with LLM ones flagged so the drawer can show their
        # SPL/KQL queries directly), techniques, IOCs, and a severity
        # distribution. All single-pass — no extra parsing.
        pub = a.get("published", "")
        for actor in a.get("_actors", []):
            entry = actor_index.setdefault(actor, {
                "name": actor,
                "country": _ACTOR_BY_NAME.get(actor, {}).get("country", "??"),
                "flag":    _ACTOR_BY_NAME.get(actor, {}).get("flag", "🌐"),
                "motivation": _ACTOR_BY_NAME.get(actor, {}).get("motivation", "unknown"),
                "aliases": _ACTOR_BY_NAME.get(actor, {}).get("aliases", [actor]),
                "mitre_id": _ACTOR_BY_NAME.get(actor, {}).get("mitre_id", ""),
                "articles": [],
                "uc_count": 0,
                "llm_uc_count": 0,
                "techs": set(),
                "tech_freq": {},  # technique frequency for "top 3" display
                "iocs": {"cves": set(), "ips": set(), "domains": set(), "hashes": set()},
                "sev_dist": {"crit": 0, "high": 0, "med": 0, "low": 0},
                "first_seen": None, "last_seen": None,
                "ucs": [],     # subset of UCs the analyst can click — LLM-bespoke first
            })
            entry["articles"].append({"id": f"art-{i:02d}", "title": a["title"], "sev": sev, "published": pub})
            entry["uc_count"] += len(ucs)
            entry["llm_uc_count"] += sum(1 for u in ucs if (u.title or "").startswith("[LLM]"))
            entry["sev_dist"][sev] = entry["sev_dist"].get(sev, 0) + 1
            for tid, _ in merged_techs:
                entry["techs"].add(tid)
                entry["tech_freq"][tid] = entry["tech_freq"].get(tid, 0) + 1
            for cve in ind.get("cves", []): entry["iocs"]["cves"].add(cve)
            for ip in ind.get("ips", []): entry["iocs"]["ips"].add(ip)
            for dom in ind.get("domains", []): entry["iocs"]["domains"].add(dom)
            for h in (ind.get("sha256",[])+ind.get("sha1",[])+ind.get("md5",[])):
                entry["iocs"]["hashes"].add(h)
            # Date tracking — articles arrive in feed order, not strict
            # publish-date order, so compare and keep min/max.
            if pub:
                if entry["first_seen"] is None or pub < entry["first_seen"]:
                    entry["first_seen"] = pub
                if entry["last_seen"] is None or pub > entry["last_seen"]:
                    entry["last_seen"] = pub
            # Stash a slim view of UCs for drawer rendering — LLM-bespoke
            # ones first (they're the article-specific high-fidelity
            # detections, the most analyst-valuable content), then fill
            # with rule-fired UCs up to a per-actor cap so the JSON
            # payload stays light. Sort the per-article UC list once
            # before iterating; preserving stable order within each tier.
            ucs_for_drawer = sorted(
                ucs,
                key=lambda u: 0 if (u.title or "").startswith("[LLM]") else 1,
            )
            for uc in ucs_for_drawer:
                if len(entry["ucs"]) >= 12: break
                title = uc.title or ""
                entry["ucs"].append({
                    "title": title,
                    "is_llm": title.startswith("[LLM]"),
                    "phase": uc.kill_chain,
                    "conf": uc.confidence,
                    "techs": [t for t,_n in (uc.techniques or [])],
                    "art_id": f"art-{i:02d}",
                    "art_title": a["title"],
                })
        safe_title = a['title'][:55].encode('ascii', 'replace').decode('ascii')
        print(f"  [{i+1:02d}] {safe_title:55s} | sev={sev:4s} techs={len(techniques)} ucs={len(ucs)} kc-hit={len(hit)}")

    nav = render_nav(nav_meta)

    # IOC aggregation across all articles
    iocs = aggregate_iocs(articles_meta)
    generated_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_intel_files(iocs, generated_iso)
    write_catalog_files(generated_iso)
    print(f"[*] IOCs aggregated: {len(iocs)} unique  ->  intel/")
    print(f"[*] Catalog exported: {len(_LOADED_UCS or {})} use cases  ->  catalog/")

    # Relevance gate end-of-run summary + audit log. The classifier sits in
    # the main article loop and decides which articles render a card; this
    # block reports what it kept / dropped and writes the per-drop reasons
    # to intel/relevance_drops.jsonl for analyst review.
    rel_kept   = (relevance_tier_counts.get("keep-0", 0)
                  + relevance_tier_counts.get("llm-2-alert", 0)
                  + relevance_tier_counts.get("default-keep", 0))
    rel_dropped = (relevance_tier_counts.get("drop-1", 0)
                   + relevance_tier_counts.get("llm-2-drop", 0))
    if rel_kept or rel_dropped:
        top_sources = {}
        for d in relevance_drop_log:
            s = d.get("source") or "?"
            top_sources[s] = top_sources.get(s, 0) + 1
        top_str = ", ".join(f"{s}:{n}" for s, n in
                            sorted(top_sources.items(), key=lambda x:-x[1])[:5])
        print(
            f"[*] Relevance: kept {rel_kept} alert, dropped {rel_dropped} "
            f"(tier-0 override: {relevance_tier_counts.get('keep-0',0)}, "
            f"tier-1 regex: {relevance_tier_counts.get('drop-1',0)}, "
            f"tier-2 LLM: {relevance_tier_counts.get('llm-2-alert',0)} alert / "
            f"{relevance_tier_counts.get('llm-2-drop',0)} drop, "
            f"default-keep: {relevance_tier_counts.get('default-keep',0)})"
        )
        if top_str:
            print(f"    Top dropped sources: {top_str}")
    try:
        drops_path = Path(__file__).parent / "intel" / "relevance_drops.jsonl"
        drops_path.parent.mkdir(parents=True, exist_ok=True)
        with drops_path.open("w", encoding="utf-8") as fh:
            for d in relevance_drop_log:
                fh.write(__import__("json").dumps(d, ensure_ascii=False) + "\n")
    except Exception as _e:
        print(f"    [!] relevance_drops.jsonl write failed: {_e}")

    # Per-article briefings — committed to the repo so anyone pulling sees
    # operational content, not just aggregate exports
    raw_index = {f"art-{i:02d}": a for i, a in enumerate(articles)}
    briefing_paths = write_briefings(articles_meta, raw_index)
    print(f"[*] Briefings written: {len(briefing_paths)}  ->  briefings/")
    # Per-target redirect stubs at share/{article,uc}/<slug>.html so chat
    # apps unfurl shared deeplinks with proper og:* previews. Bots scrape
    # the stub; humans get redirected to the in-app hash URL in <50 ms.
    write_share_stubs(articles_meta, raw_index)

    intel_json = __import__("json").dumps({"generated": generated_iso, "iocs": iocs}, default=str)

    # Source filter chips (Articles tab)
    src_class_map_chips = {
        "The Hacker News": "thn",
        "BleepingComputer": "bc",
        "Microsoft Security Blog": "ms",
        "CISA KEV": "kev",
        "Cisco Talos": "talos",
        "Securelist (Kaspersky)": "securelist",
        "SentinelLabs": "sentinel",
        "Unit 42 (Palo Alto)": "unit42",
        "ESET WeLiveSecurity": "eset",
        "Lab52": "lab52",
        "Cyber Security News": "csn",
    }
    src_counts = {}
    for a in articles:
        for s in (a.get("sources") or [a.get("source", "")]):
            src_counts[s] = src_counts.get(s, 0) + 1
    chip_html = [
        f'<span class="lg-label">Source</span>',
        f'<button class="src-chip all active" data-source="">All <span class="cnt">{len(articles)}</span></button>',
    ]
    for src in [s["name"] for s in SOURCES]:
        cnt = src_counts.get(src, 0)
        if cnt == 0: continue
        cls = src_class_map_chips.get(src, "")
        label = {"The Hacker News":"THN","BleepingComputer":"BleepingComputer",
                 "Microsoft Security Blog":"Microsoft","CISA KEV":"CISA KEV",
                 "Cisco Talos":"Talos","Securelist (Kaspersky)":"Securelist",
                 "SentinelLabs":"SentinelLabs","Unit 42 (Palo Alto)":"Unit 42",
                 "ESET WeLiveSecurity":"ESET"}.get(src, src)
        chip_html.append(
            f'<button class="src-chip {cls}" data-source="{html.escape(src)}">'
            f'{html.escape(label)} <span class="cnt">{cnt}</span></button>')
    source_chips_html = "\n".join(chip_html)

    matrix_data = build_matrix_data(articles_meta)
    if matrix_data:
        print(f"[*] Matrix: {matrix_data['stats']['total_techs']} techniques, "
              f"{matrix_data['stats']['total_subs']} sub-techniques, "
              f"{matrix_data['stats']['covered_techs']} with use-case or article coverage")
        # Emit a static HTML landing page per technique. Indexable + linkable
        # individually — every T-ID gets /techniques/<TID>.html with UC list,
        # article list, MITRE link, and JSON-LD structured data.
        write_technique_pages(matrix_data)
    matrix_json = __import__("json").dumps(matrix_data) if matrix_data else "null"

    # ===== MITRE-sourced groups =====================================
    # Pull every intrusion-set in the MITRE ATT&CK catalog and merge
    # them into actor_index so the Threat Actors tab shows the full
    # ~170-group reference, not just the ~30 actors mentioned in
    # recent articles.
    #
    # For each MITRE group:
    #  - merge with our manual entry if name/alias overlaps (manual
    #    entry's country + motivation win)
    #  - else create a new entry with country/motivation derived from
    #    a small heuristic table (see _mitre_country_for / _mitre_mot_for)
    #  - link UCs by intersecting the group's MITRE techniques with
    #    catalog UCs that target those techniques. These come out as
    #    'mitre-derived' entries flagged is_mitre_match=True so the
    #    drawer can label them differently from article-driven UCs.
    try:
        reg = __import__("json").loads(REGISTRY_PATH_FOR_MATRIX.read_text(encoding="utf-8"))
        mitre_groups = reg.get("attack_groups") or {}
    except Exception as _e:
        print(f"[!] Failed to load attack_groups from registry: {_e}")
        reg = {}
        mitre_groups = {}
    print(f"[*] MITRE attack_groups loaded: {len(mitre_groups)}")

    # Country / motivation overrides for MITRE groups whose attribution
    # is well-known but not encoded in the STIX bundle. Keyed by canonical
    # name; covers the major nation-state actors. Anything not listed
    # falls back to "??" / "unknown".
    _MITRE_COUNTRY = {
        # Russia
        "APT28":"RU","APT29":"RU","Sandworm Team":"RU","Turla":"RU","Gamaredon Group":"RU",
        "Dragonfly":"RU","Cadet Blizzard":"RU","FIN7":"RU","TA505":"RU","Wizard Spider":"RU",
        "BlackByte":"RU","INC Ransom":"RU","RomCom":"RU","TEMP.Veles":"RU","FIN8":"RU",
        # China
        "APT41":"CN","APT10":"CN","APT3":"CN","APT12":"CN","APT16":"CN","APT17":"CN",
        "APT18":"CN","APT19":"CN","APT26":"CN","APT30":"CN","Volt Typhoon":"CN",
        "Salt Typhoon":"CN","Silk Typhoon":"CN","Mustang Panda":"CN","GALLIUM":"CN",
        "Storm-0558":"CN","Earth Lusca":"CN","Tropic Trooper":"CN","Naikon":"CN",
        "Threat Group-3390":"CN","Axiom":"CN","Deep Panda":"CN","Suckfly":"CN",
        "Stone Panda":"CN","Hafnium":"CN","Aoqin Dragon":"CN","Daggerfly":"CN",
        "Liminal Panda":"CN","Flax Typhoon":"CN","Linen Typhoon":"CN","Granite Typhoon":"CN",
        "Storm-2077":"CN","Brass Typhoon":"CN","MirrorFace":"CN","BlackTech":"CN",
        # North Korea
        "Lazarus Group":"KP","Kimsuky":"KP","APT37":"KP","APT38":"KP","Andariel":"KP",
        "BlueNoroff":"KP","Moonstone Sleet":"KP","Citrine Sleet":"KP","Famous Chollima":"KP",
        # Iran
        "APT33":"IR","APT34":"IR","APT35":"IR","APT39":"IR","MuddyWater":"IR",
        "Imperial Kitten":"IR","Pioneer Kitten":"IR","Magic Hound":"IR",
        "Charming Kitten":"IR","OilRig":"IR","Refined Kitten":"IR","Cyber Av3ngers":"IR",
        # Pakistan / India
        "Transparent Tribe":"PK","SideCopy":"PK","Patchwork":"IN","SideWinder":"IN",
        # Vietnam
        "APT32":"VN",
        # Lebanon
        "Volatile Cedar":"LB",
        # Brazil
        "LAPSUS$":"BR","Lapsus$":"BR",
        # USA / Five Eyes
        "Equation":"US","Scattered Spider":"US","Tortoiseshell":"US",
    }
    _COUNTRY_FLAGS = {
        "RU":"🇷🇺","CN":"🇨🇳","KP":"🇰🇵","IR":"🇮🇷","IN":"🇮🇳","PK":"🇵🇰",
        "VN":"🇻🇳","MY":"🇲🇾","LB":"🇱🇧","BR":"🇧🇷","US":"🇺🇸","??":"🌐"
    }

    def _motivation_for(group_name, group_aliases):
        """Heuristic: state if it's an APT-style nation-state actor;
        criminal if name/alias mentions ransomware / e-crime keywords;
        else unknown."""
        text = (group_name + " " + " ".join(group_aliases)).lower()
        if any(s in text for s in ["ransom", "evil corp", "darkside", "blackcat", "alphv",
                                    "lockbit", "conti", "revil", "cl0p", "clop", "akira",
                                    "play ransomware", "qilin", "medusa", "trinity",
                                    "ta505", "fin6", "fin7", "fin8", "fin11", "blackbasta",
                                    "rhysida", "hellcat", "embargo", "stormous", "killsec",
                                    "wizard spider", "gold ", "indrik spider"]):
            return "criminal"
        if any(s in text for s in ["apt", "bear", "panda", "kitten", "tiger", "leopard",
                                    "buffalo", "spider apt", "typhoon", "blizzard", "sleet",
                                    "sandstorm", "chollima", "lazarus", "kimsuky",
                                    "muddywater", "turla", "sandworm", "gamaredon",
                                    "transparent tribe", "patchwork", "sidewinder",
                                    "oceanlotus", "cyber av3ngers", "volatile cedar"]):
            return "state"
        return "unknown"

    # Build alias -> canonical actor name lookup so we can merge
    # MITRE entries into our manually-curated ones.
    _existing_alias_lc = {}
    for k, e in actor_index.items():
        for a in e.get("aliases", []) + [e["name"]]:
            _existing_alias_lc[a.lower()] = k

    # Pre-compute: for each technique id, which of the catalog's UCs
    # cover it. We use _LOADED_UCS plus the matrix sidecar (built from
    # ESCU detections + internal yaml UCs) so the join works against
    # the full ~2238-entry catalog.
    techs_to_ucs = {}      # tid -> [{name, source, splunk, kql, conf, kc, src_id}]
    if _LOADED_UCS:
        for uc_id, uc in _LOADED_UCS.items():
            for tid, _tname in (uc.techniques or []):
                techs_to_ucs.setdefault(tid, []).append({
                    "name": uc.title,
                    "source": "internal",
                    "src_id": uc_id,
                    "kc": uc.kill_chain,
                    "conf": uc.confidence,
                    "splunk": uc.splunk_spl or "",
                    "kql": uc.defender_kql or "",
                    "techs": [t for t,_ in (uc.techniques or [])],
                })
    try:
        for det in ((reg or {}).get("escu_detections") or []):
            for tid in (det.get("techniques") or []):
                techs_to_ucs.setdefault(tid, []).append({
                    "name": det.get("name") or "",
                    "source": "splunk_escu",
                    "src_id": (det.get("id") or "")[:36],
                    "kc": (det.get("kill_chain_phases") or [""])[0],
                    "conf": det.get("type", "Detection"),
                    "splunk": det.get("search", ""),
                    "kql": "",
                    "techs": det.get("techniques") or [],
                })
    except Exception:
        pass

    mitre_added = 0
    mitre_merged = 0
    for gid, g in (mitre_groups or {}).items():
        gname = g["name"]
        existing = None
        for alias in g["aliases"]:
            cand = _existing_alias_lc.get(alias.lower())
            if cand:
                existing = cand; break
        country = _MITRE_COUNTRY.get(gname, "??")
        motivation = _motivation_for(gname, g["aliases"])
        techs = g.get("techniques") or []
        if existing:
            # Merge into existing entry — augment aliases + techniques,
            # don't override country/motivation (manual catalog wins).
            entry = actor_index[existing]
            for a in g["aliases"]:
                if a not in entry["aliases"]:
                    entry["aliases"].append(a)
            for tid in techs:
                entry["techs"].add(tid)
            if not entry.get("mitre_id"):
                entry["mitre_id"] = gid
            mitre_merged += 1
        else:
            # New MITRE-only entry. No article references; UCs come
            # purely from technique→UC matching.
            actor_index[gname] = {
                "name": gname,
                "country": country,
                "flag": _COUNTRY_FLAGS.get(country, "🌐"),
                "motivation": motivation,
                "aliases": g["aliases"],
                "mitre_id": gid,
                "articles": [],
                "uc_count": 0,
                "llm_uc_count": 0,
                "techs": set(techs),
                "tech_freq": {tid: 1 for tid in techs},
                "iocs": {"cves": set(), "ips": set(), "domains": set(), "hashes": set()},
                "sev_dist": {"crit":0, "high":0, "med":0, "low":0},
                "first_seen": None, "last_seen": None,
                "ucs": [],
                "is_mitre_only": True,
                "mitre_description": g.get("description", "")[:600],
            }
            mitre_added += 1
        # Build UCs for this group from technique matching. Cap at 12
        # to keep payload light and prefer alerting-tier internal ones.
        entry = actor_index.get(existing) or actor_index.get(gname)
        if not entry: continue
        seen = set((u.get("name") for u in entry["ucs"]))
        candidates = []
        for tid in techs:
            for uc in (techs_to_ucs.get(tid) or [])[:6]:
                if uc["name"] in seen: continue
                candidates.append(uc)
                seen.add(uc["name"])
        # Prefer LLM-prefixed (none here, but future-proof) then internal then ESCU
        candidates.sort(key=lambda u: (
            0 if (u["name"] or "").startswith("[LLM]") else 1,
            0 if u["source"] == "internal" else 1,
            (u["name"] or "").lower(),
        ))
        for uc in candidates[:12]:
            if len(entry["ucs"]) >= 24: break  # generous slim cap for MITRE-rich actors
            entry["ucs"].append({
                "title": uc["name"],
                "is_llm": (uc["name"] or "").startswith("[LLM]"),
                "phase": uc["kc"],
                "conf": uc["conf"],
                "techs": uc["techs"][:5],
                "art_id": "",
                "art_title": "",
                "is_mitre_match": True,
                "splunk": uc["splunk"],
                "kql": uc["kql"],
            })

    print(f"[*] MITRE Groups merged: {mitre_added} new + {mitre_merged} merged into existing actors")

    # ===== Per-actor LLM-bespoke UCs ===================================
    # For each actor (article-bound + MITRE-only) with a meaningful
    # technique profile, ask the LLM to produce 1-2 high-fidelity
    # detections tied to THIS actor's specific tradecraft. Cached on
    # disk by actor name + technique signature so subsequent runs are
    # free; only newly-added actors or technique-set changes incur LLM
    # cost. UCs come back flagged source_kind='actor-bespoke' so the
    # drawer can label them ('LLM · actor profile' vs the existing
    # article-bound 'LLM' tag).
    actor_llm_added = 0
    actor_llm_skipped = 0
    actor_llm_total = 0
    for entry in list(actor_index.values()):
        actor_llm_total += 1
        # Build a flat actor dict for the LLM helper
        try:
            new_ucs = _llm_generate_actor_ucs({
                "name": entry["name"],
                "country": entry["country"],
                "motivation": entry["motivation"],
                "aliases": entry["aliases"],
                "mitre_id": entry["mitre_id"],
                "techs": sorted(entry["techs"]),
                "mitre_description": entry.get("mitre_description", ""),
            })
        except Exception as _e:
            print(f"    [!] actor-LLM exception for {entry['name']}: {_e}")
            new_ucs = []
        if new_ucs:
            # Prepend: LLM-bespoke profile UCs sit at the top of the
            # drawer's UC list, above article-bound and MITRE-match.
            entry["ucs"] = new_ucs + entry["ucs"]
            entry["llm_uc_count"] = (entry.get("llm_uc_count") or 0) + len(new_ucs)
            actor_llm_added += len(new_ucs)
        else:
            actor_llm_skipped += 1
    print(f"[*] Actor-bespoke LLM UCs: {actor_llm_added} generated across {actor_llm_total - actor_llm_skipped}/{actor_llm_total} actors (skipped: sparse profile or no auth)")

    # Threat-actor payload — sets are converted to sorted lists for JSON.
    actors_serialisable = []
    for entry in actor_index.values():
        # Top-3 techniques by frequency for the card preview
        top_techs = sorted(entry["tech_freq"].items(), key=lambda kv: -kv[1])[:3]
        actors_serialisable.append({
            "name": entry["name"],
            "country": entry["country"],
            "flag": entry["flag"],
            "motivation": entry["motivation"],
            "aliases": entry["aliases"],
            "mitre_id": entry["mitre_id"],
            "articles": entry["articles"],
            "uc_count": entry["uc_count"] + sum(1 for u in entry["ucs"] if u.get("is_mitre_match")),
            "llm_uc_count": entry["llm_uc_count"],
            "techs": sorted(entry["techs"]),
            "top_techs": [t for t, _c in top_techs] if top_techs else sorted(entry["techs"])[:3],
            "iocs": {k: sorted(v) for k, v in entry["iocs"].items()},
            "sev_dist": entry["sev_dist"],
            "first_seen": entry["first_seen"] or "",
            "last_seen": entry["last_seen"] or "",
            "ucs": entry["ucs"],
            "is_mitre_only": entry.get("is_mitre_only", False),
            "mitre_description": entry.get("mitre_description", ""),
        })
    # Sort: actors with article references first (most active), then
    # MITRE-only by name. So the analyst sees recent-news actors at
    # the top; MITRE-catalog reference entries follow.
    actors_serialisable.sort(key=lambda e: (
        0 if not e.get("is_mitre_only") else 1,
        -len(e["articles"]),
        -e["uc_count"],
        e["name"]
    ))
    actors_json = __import__("json").dumps(actors_serialisable, separators=(",", ":"))
    print(f"[*] Threat actors detected: {len(actors_serialisable)} unique  ->  page payload")
    # Static per-actor landing pages — same SEO + share pattern as the
    # technique pages: one indexable URL per actor at /actors/<slug>.html
    # with profile, UCs, articles, IOCs, MITRE link.
    if matrix_data:
        write_actor_pages(actors_serialisable, matrix_data.get("techniques") or {})
        write_target_pages(matrix_data)
    else:
        write_actor_pages(actors_serialisable, {})

    page = (
        HTML_HEAD
        .replace("__GENERATED_AT__", dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
        .replace("__ARTICLE_COUNT__", str(len(articles)))
        .replace("__USECASE_COUNT__", str(total_ucs))
        .replace("__TECH_COUNT__", str(len(total_techs)))
        .replace("__CVE_COUNT__", str(len(total_cves)))
        .replace("__CRIT_COUNT__", str(sev_counts["crit"] + sev_counts["high"]))
        .replace("__NAV__", nav)
        .replace("__CARDS__", "\n".join(cards))
        .replace("__SOURCE_CHIPS__", source_chips_html)
        .replace("__MATRIX_DATA__", matrix_json)
        .replace("__INTEL_DATA__", intel_json)
        .replace("__ACTORS_DATA__", actors_json)
    )
    OUT_HTML.write_text(page, encoding="utf-8")
    print(f"[*] Wrote {OUT_HTML} ({OUT_HTML.stat().st_size//1024} KB)")
    print(f"    Severity: crit={sev_counts['crit']} high={sev_counts['high']} med={sev_counts['med']} low={sev_counts['low']}")
    print(f"    Bespoke article-specific UCs built: {bespoke_built}")

    # SEO sitemap.xml — refresh every pipeline run so Google's crawler
    # knows about freshly-published per-article briefings. Includes the
    # main site, the cheatsheet, and every briefings/<date>/<slug>.md
    # file rendered through GitHub raw URLs (those pages are search-
    # engine-friendly per-article content; the SPA itself is one giant
    # blob that Google struggles to index).
    try:
        import datetime as _dt
        from pathlib import Path as _Path
        today_iso = _dt.date.today().isoformat()
        sitemap_urls = [
            ("https://clankerusecase.com/", "1.0", "hourly"),
            ("https://clankerusecase.com/index.html", "1.0", "hourly"),
            ("https://clankerusecase.com/cheatsheet.html", "0.9", "daily"),
        ]
        briefings_root = _Path(__file__).with_name("briefings")
        if briefings_root.exists():
            for date_dir in sorted(briefings_root.iterdir()):
                if not date_dir.is_dir():
                    continue
                for md in sorted(date_dir.glob("*.md")):
                    rel = md.relative_to(_Path(__file__).parent).as_posix()
                    sitemap_urls.append(
                        (f"https://github.com/Virtualhaggis/usecaseintel/blob/main/{rel}",
                         "0.6", "monthly")
                    )
        # Per-technique landing pages. One indexable URL per MITRE T-ID
        # at techniques/<TID>.html — high-value SEO surface.
        techniques_root = _Path(__file__).with_name("techniques")
        if techniques_root.exists():
            for tp in sorted(techniques_root.glob("*.html")):
                sitemap_urls.append(
                    (f"https://clankerusecase.com/techniques/{tp.name}",
                     "0.7", "weekly")
                )
        # Per-actor landing pages.
        actors_root = _Path(__file__).with_name("actors")
        if actors_root.exists():
            for ap in sorted(actors_root.glob("*.html")):
                sitemap_urls.append(
                    (f"https://clankerusecase.com/actors/{ap.name}",
                     "0.7", "weekly")
                )
        # Per-target (OS / cloud / SaaS) landing pages.
        targets_root = _Path(__file__).with_name("targets")
        if targets_root.exists():
            for tp in sorted(targets_root.glob("*.html")):
                sitemap_urls.append(
                    (f"https://clankerusecase.com/targets/{tp.name}",
                     "0.8", "weekly")
                )
        sitemap_urls = sitemap_urls[:50000]  # protocol cap
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                     '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
        for loc, prio, freq in sitemap_urls:
            xml_lines.append("  <url>")
            xml_lines.append(f"    <loc>{html.escape(loc)}</loc>")
            xml_lines.append(f"    <lastmod>{today_iso}</lastmod>")
            xml_lines.append(f"    <changefreq>{freq}</changefreq>")
            xml_lines.append(f"    <priority>{prio}</priority>")
            xml_lines.append("  </url>")
        xml_lines.append("</urlset>")
        _Path(__file__).with_name("sitemap.xml").write_text(
            "\n".join(xml_lines) + "\n", encoding="utf-8")
        print(f"[*] Wrote sitemap.xml ({len(sitemap_urls)} URLs)")
    except Exception as _e:
        print(f"[!] sitemap.xml write failed: {_e}")


if __name__ == "__main__":
    main()
