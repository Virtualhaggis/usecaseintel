"""One-shot Discord server restructure for Clankerusecase.

Reads bot token from .discord_bot_token. Idempotent: re-running won't
create duplicates — it matches on existing names and only fills gaps.

What it does:
- Ensures categories exist (📌 INFO, 🛡 DETECTION, 🐛 REPORT-AN-ISSUE,
  💡 REQUESTS, 🔒 STAFF) with stable channel-ordering.
- Ensures new text channels exist (announcements, introductions,
  wins-and-catches, logic-issues, false-positives).
- Moves existing channels into the right categories.
- Posts a pinned report-template in logic-issues and false-positives
  if no template message is already pinned there.
- Sets a server description.
"""
from __future__ import annotations
import json, sys, time
from pathlib import Path
from urllib import request, error, parse

ROOT = Path(__file__).parent
TOKEN = (ROOT / ".discord_bot_token").read_text(encoding="utf-8").strip()
GUILD_ID = "1499498000677081108"
API = "https://discord.com/api/v10"

HEADERS = {
    "Authorization": f"Bot {TOKEN}",
    "Content-Type": "application/json",
    "User-Agent": "ClankerusecaseManager/1.0 (Python)",
    "X-Audit-Log-Reason": "automated-restructure",
}


def api(method: str, path: str, body=None, retries=3):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    req = request.Request(url, data=data, headers=HEADERS, method=method)
    for attempt in range(retries):
        try:
            with request.urlopen(req) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except error.HTTPError as e:
            payload = e.read().decode("utf-8", errors="replace")
            if e.code == 429:
                # rate-limit: respect Retry-After
                try:
                    info = json.loads(payload)
                    wait = float(info.get("retry_after", 1.0))
                except Exception:
                    wait = 1.5
                print(f"  rate-limited, waiting {wait:.1f}s")
                time.sleep(wait + 0.2)
                continue
            print(f"  HTTP {e.code} on {method} {path}: {payload[:300]}")
            raise
        except error.URLError as e:
            if attempt == retries - 1:
                raise
            time.sleep(1.0)


def list_channels():
    return api("GET", f"/guilds/{GUILD_ID}/channels")


def create_channel(name: str, type_: int, parent_id: str | None = None, topic: str | None = None):
    body = {"name": name, "type": type_}
    if parent_id:
        body["parent_id"] = parent_id
    if topic:
        body["topic"] = topic
    return api("POST", f"/guilds/{GUILD_ID}/channels", body)


def patch_channel(cid: str, body: dict):
    return api("PATCH", f"/channels/{cid}", body)


def post_message(cid: str, content: str):
    return api("POST", f"/channels/{cid}/messages", {"content": content})


def pin_message(cid: str, mid: str):
    return api("PUT", f"/channels/{cid}/pins/{mid}", body=None)


def get_pins(cid: str):
    try:
        return api("GET", f"/channels/{cid}/pins")
    except Exception:
        return []


def patch_guild(body: dict):
    return api("PATCH", f"/guilds/{GUILD_ID}", body)


# ---------- Plan ----------

CATEGORIES_DESIRED = [
    ("📌 INFO",            "info"),
    ("🛡 DETECTION",       "detection"),
    ("🐛 REPORT-AN-ISSUE", "report"),
    ("💡 REQUESTS",         "requests"),
    ("🔒 STAFF",            "staff"),
]

# desired-name -> (category-key, topic, type=text)
TEXT_CHANNELS = [
    # INFO
    ("announcements",     "info",      "Daily digest + product news. Read-only — auto-posted from the pipeline."),
    ("rules",             "info",      "Server rules. Read before posting."),
    ("welcome",           "info",      "Welcome banner — what the server is for."),
    ("introductions",     "info",      "Say hi! Tell us your role + what you're hunting."),
    # DETECTION
    ("general",           "detection", "Open chat for SOC analysts."),
    ("detection-engineering", "detection", "Building, tuning, and reviewing detections. KQL / SPL / Sigma / Datadog."),
    ("threat-hunting",    "detection", "Hunt hypotheses, IOCs, and methodology."),
    ("wins-and-catches",  "detection", "Share what your tuned UC actually caught — with redactions."),
    # REPORT AN ISSUE
    ("logic-issues",      "report",    "Bugs in the *query logic* of a published UC (KQL/SPL/Sigma/Datadog). Use the pinned template."),
    ("false-positives",   "report",    "UCs that fire on benign activity in your environment."),
    ("site-feedback",     "report",    "UI / site bugs on clankerusecase.com."),
    # REQUESTS
    ("use-case-requests", "requests",  "Request a new detection UC for an attack technique or article."),
    ("platform-requests", "requests",  "Request a SIEM / EDR / XDR platform we don't yet emit."),
    # STAFF
    ("moderator-only",    "staff",     "Mod / staff coordination."),
]

LOGIC_ISSUES_TEMPLATE = (
    "**Logic Issue Report Template** — paste this in a new post and fill it in.\n\n"
    "**UC URL:** https://clankerusecase.com/#uc-...\n"
    "**Platform:** Defender KQL / Sentinel KQL / Splunk SPL / Sigma / Datadog\n"
    "**Expected behaviour:** what should this query catch?\n"
    "**Actual behaviour:** what it does instead (false-negative / errors / wrong field)\n"
    "**Sample log / repro steps:** redacted log line that should have matched but didn't (or matched but shouldn't)\n"
    "**Suggested fix (optional):** if you've already got a working version, paste it"
)

FALSE_POSITIVES_TEMPLATE = (
    "**False-Positive Report Template** — paste this and fill it in.\n\n"
    "**UC URL:** https://clankerusecase.com/#uc-...\n"
    "**Platform:** Defender KQL / Sentinel KQL / Splunk SPL / Sigma / Datadog\n"
    "**FP context:** what benign activity is firing the rule? (vendor tool, scheduled job, admin behaviour…)\n"
    "**Volume:** roughly how many FPs per day in your env\n"
    "**Suggested filter (optional):** the predicate you'd add to suppress without losing the true-positive case"
)

GUILD_DESCRIPTION = (
    "High-fidelity SOC detection content, generated daily from threat-intel feeds. "
    "KQL, SPL, Sigma, Datadog Cloud SIEM. Drop logic bugs, FPs, and UC requests here."
)


def slug(s: str) -> str:
    """Normalise channel name to Discord's lowercase-dash form for matching."""
    return s.lower().replace(" ", "-").replace("_", "-")


def main() -> int:
    print("→ fetching current channels")
    chans = list_channels()
    by_id = {c["id"]: c for c in chans}
    by_slug_type = {(slug(c["name"]), c["type"]): c for c in chans}

    # ---- ensure categories ----
    cat_id = {}
    for full_name, key in CATEGORIES_DESIRED:
        # Match by trailing word (INFO / DETECTION / etc) — emojis can drop
        match = None
        for c in chans:
            if c["type"] != 4:
                continue
            cn = c["name"].upper()
            kn = full_name.split(" ")[-1].upper()
            if kn in cn:
                match = c
                break
        if match:
            print(f"  category exists: {match['name']}  ({match['id']})")
            cat_id[key] = match["id"]
            # Ensure name is the canonical full form (with emoji)
            if match["name"] != full_name:
                patch_channel(match["id"], {"name": full_name})
                print(f"    renamed → {full_name}")
        else:
            print(f"  creating category: {full_name}")
            c = create_channel(full_name, 4)
            cat_id[key] = c["id"]
            time.sleep(0.3)

    # Refresh after creates
    chans = list_channels()
    by_slug_type = {(slug(c["name"]), c["type"]): c for c in chans}

    # ---- ensure text channels exist + parented correctly ----
    for name, cat_key, topic in TEXT_CHANNELS:
        parent = cat_id[cat_key]
        existing = by_slug_type.get((slug(name), 0))
        if existing:
            patch_body = {}
            if existing.get("parent_id") != parent:
                patch_body["parent_id"] = parent
            if topic and (existing.get("topic") or "") != topic:
                patch_body["topic"] = topic
            if patch_body:
                patch_channel(existing["id"], patch_body)
                print(f"  updated #{name} ({list(patch_body)})")
            else:
                print(f"  #{name} already in place")
        else:
            print(f"  creating #{name} under {cat_key}")
            create_channel(name, 0, parent_id=parent, topic=topic)
            time.sleep(0.3)

    # ---- pin templates ----
    chans = list_channels()
    by_slug_type = {(slug(c["name"]), c["type"]): c for c in chans}
    for ch_name, template in [
        ("logic-issues",   LOGIC_ISSUES_TEMPLATE),
        ("false-positives", FALSE_POSITIVES_TEMPLATE),
    ]:
        ch = by_slug_type.get((ch_name, 0))
        if not ch:
            continue
        pins = get_pins(ch["id"]) or []
        already = any("Report Template" in (p.get("content") or "") for p in pins)
        if already:
            print(f"  #{ch_name} template already pinned")
            continue
        msg = post_message(ch["id"], template)
        time.sleep(0.4)
        pin_message(ch["id"], msg["id"])
        print(f"  pinned template in #{ch_name}")
        time.sleep(0.3)

    # ---- server description (Community-only feature; ignore if rejected) ----
    try:
        patch_guild({"description": GUILD_DESCRIPTION})
        print("  guild description set")
    except error.HTTPError as e:
        print(f"  (guild description skipped: HTTP {e.code} — needs Community server)")

    print("\n✓ done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
