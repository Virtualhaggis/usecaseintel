"""
sync.py — Pull authoritative Splunk + MITRE sources and build a local
registry.json that validate.py and generate.py can use.

Sources (all public, no auth required):
  1. splunk/security_content (develop branch tarball)        -> ESCU detections
  2. mitre-attack/attack-stix-data (master)                  -> ATT&CK techniques
  3. derived CIM dataset/field registry                       -> from ESCU YAMLs
                                                                (this is the field
                                                                 set actually used in
                                                                 production Splunk
                                                                 content)

Run:    py sync.py
Output: thn-usecases/data_sources/registry.json
        thn-usecases/data_sources/sync_log.json
        thn-usecases/CHANGELOG.md (appended)
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import tarfile
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("[FATAL] PyYAML required. pip install pyyaml")

ROOT = Path(__file__).parent
DATA = ROOT / "data_sources"
DATA.mkdir(exist_ok=True)
REGISTRY_PATH = DATA / "registry.json"
LOG_PATH = DATA / "sync_log.json"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"

UA = "Mozilla/5.0 (compatible; thn-usecases-sync/1.0)"

SOURCES = {
    "splunk_security_content": {
        "url": "https://github.com/splunk/security_content/archive/refs/heads/develop.tar.gz",
        "kind": "tarball",
    },
    "mitre_attack": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "kind": "json",
    },
    "defender_hunting_queries": {
        "url": "https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/archive/refs/heads/master.tar.gz",
        "kind": "tarball",
    },
}

# Regex: find dataset references in SPL ----------------------------------------
DM_PATH_RE = re.compile(r"from\s+datamodel\s*=\s*([\w.]+)", re.IGNORECASE)
NODENAME_RE = re.compile(r'nodename\s*=\s*"([\w.]+)"', re.IGNORECASE)
SHORT_DS_FIELD_RE = re.compile(r"\b([A-Z][A-Za-z_]+)\.([a-z][\w]+)\b")


# -------- Fetchers ------------------------------------------------------------

def http_get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_security_content():
    print("[*] Downloading splunk/security_content (develop tarball)…")
    raw = http_get(SOURCES["splunk_security_content"]["url"])
    print(f"    {len(raw)//1024} KB downloaded")
    detections, macros = [], []
    skipped = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.name.endswith(".yml"):
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            try:
                doc = yaml.safe_load(f.read().decode("utf-8"))
            except Exception:
                skipped += 1
                continue
            if not isinstance(doc, dict):
                continue
            path = m.name
            if "/detections/" in path:
                detections.append(doc)
            elif "/macros/" in path:
                macros.append(doc)
    print(f"    detections: {len(detections)}, macros: {len(macros)}, skipped: {skipped}")
    return detections, macros


def fetch_defender_queries():
    """
    Pull microsoft/Microsoft-365-Defender-Hunting-Queries (official Microsoft
    repo of KQL hunting examples), extract KQL code blocks from .md/.txt/.kql,
    and return a list of {path, kql} dicts.
    """
    print("[*] Downloading microsoft/Microsoft-365-Defender-Hunting-Queries…")
    raw = http_get(SOURCES["defender_hunting_queries"]["url"])
    print(f"    {len(raw)//1024} KB downloaded")
    queries = []
    md_codeblock_re = re.compile(r"```(?:kql|kusto|KQL)?\s*\n(.*?)```", re.DOTALL)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not (m.name.endswith(".md") or m.name.endswith(".kql") or m.name.endswith(".txt")):
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            try:
                text = f.read().decode("utf-8", errors="ignore")
            except Exception:
                continue
            if m.name.endswith(".md"):
                blocks = md_codeblock_re.findall(text)
                for b in blocks:
                    if any(t in b for t in DEFENDER_TABLES_HINT):
                        queries.append({"path": m.name, "kql": b.strip()})
            elif m.name.endswith((".kql", ".txt")):
                if any(t in text for t in DEFENDER_TABLES_HINT):
                    queries.append({"path": m.name, "kql": text.strip()})
    print(f"    KQL blocks parsed: {len(queries)}")
    return queries


# Defender XDR Advanced Hunting tables (used as anchors when extracting KQL
# from generic markdown). Reference:
# https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
DEFENDER_TABLES_HINT = [
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
    "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceImageLoadEvents",
    "DeviceEvents", "DeviceInfo", "DeviceNetworkInfo",
    "DeviceFileCertificateInfo",
    "EmailEvents", "EmailUrlInfo", "EmailAttachmentInfo", "EmailPostDeliveryEvents",
    "UrlClickEvents",
    "IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents", "IdentityInfo",
    "CloudAppEvents",
    "DeviceTvmSoftwareInventory", "DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareVulnerabilitiesKB",
    "DeviceTvmSecureConfigurationAssessment", "DeviceTvmSecureConfigurationAssessmentKB",
    "AlertInfo", "AlertEvidence",
    "AADSignInEventsBeta", "AADSpnSignInEventsBeta",
]


def derive_defender_registry(queries):
    """
    From the corpus of real KQL queries, build:
      tables   : {TableName: [columns_seen_sorted]}
      actions  : {TableName: {ActionType_value: count}} (where ActionType used)
      hints    : {TableName: count}                     (popularity)
    """
    tables = {}
    actions = {}
    hints = Counter()

    table_re = re.compile(r"\b(" + "|".join(re.escape(t) for t in DEFENDER_TABLES_HINT) + r")\b")
    # Column references: TableName.Column or pipe-where on bare Column.
    pipe_where_re = re.compile(r"\|\s*where\s+([A-Z][A-Za-z0-9_]+)\b")
    pipe_project_re = re.compile(r"\|\s*project\s+([^|]+)")
    pipe_summarize_re = re.compile(r"\|\s*summarize\b[^|]*\bby\s+([^|]+)")
    extend_re = re.compile(r"\|\s*extend\s+([A-Z][A-Za-z0-9_]+)\s*=")
    table_dot_col_re = re.compile(r"\b(" + "|".join(re.escape(t) for t in DEFENDER_TABLES_HINT) + r")\.([A-Z][A-Za-z0-9_]+)")
    actiontype_eq_re = re.compile(r'\bActionType\s*(?:==|=~|in~?)\s*\(?\s*"([^"]+)"')
    column_token_re = re.compile(r"\b([A-Z][A-Za-z0-9_]{2,})\b")

    for q in queries:
        kql = q["kql"]
        # Tables seen in this query
        seen_tables = set(table_re.findall(kql))
        for t in seen_tables:
            tables.setdefault(t, set())
            hints[t] += 1
        # Cols via Table.Col
        for t, col in table_dot_col_re.findall(kql):
            tables[t].add(col)
        # ActionType values
        for m in actiontype_eq_re.finditer(kql):
            val = m.group(1)
            for t in seen_tables:
                actions.setdefault(t, Counter())[val] += 1
        # Cols via | project / | extend / | where on the dominant table.
        # Without proper KQL parsing we attribute these to *every* table
        # referenced in the query — coarse but yields useful coverage.
        for col in pipe_where_re.findall(kql):
            for t in seen_tables:
                tables[t].add(col)
        for col in extend_re.findall(kql):
            for t in seen_tables:
                tables[t].add(col)
        for blk in pipe_project_re.findall(kql) + pipe_summarize_re.findall(kql):
            for col in column_token_re.findall(blk):
                if col[0].isupper():
                    for t in seen_tables:
                        tables[t].add(col)

    out_tables = {t: sorted(cols) for t, cols in tables.items() if cols}
    out_actions = {t: dict(c.most_common()) for t, c in actions.items()}
    out_hints = dict(hints.most_common())
    print(f"    tables seen: {len(out_tables)}, action-types observed: {sum(len(v) for v in out_actions.values())}")
    return out_tables, out_actions, out_hints


def fetch_attack():
    print("[*] Downloading MITRE ATT&CK enterprise-attack STIX bundle…")
    raw = http_get(SOURCES["mitre_attack"]["url"])
    print(f"    {len(raw)//1024} KB downloaded")
    bundle = json.loads(raw)
    techniques = {}      # T1234[.001] -> {name, tactics, kill_chain}
    tactics = {}         # tactic short name -> long name
    groups_raw = {}      # stix-id -> group dict (intermediate, joined later)
    rels = []            # uses-relationships joined to groups + techniques
    for obj in bundle.get("objects", []):
        t = obj.get("type")
        if t == "x-mitre-tactic":
            tactics[obj.get("x_mitre_shortname", "")] = obj.get("name", "")
        elif t == "attack-pattern":
            tid = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    break
            if not tid:
                continue
            kc = [p.get("phase_name") for p in obj.get("kill_chain_phases", []) if p.get("phase_name")]
            techniques[tid] = {
                "name": obj.get("name", ""),
                "kill_chain_phases": kc,
                "deprecated": obj.get("x_mitre_deprecated", False) or obj.get("revoked", False),
            }
        elif t == "intrusion-set":
            # MITRE-tracked threat group (APT / e-crime / hacktivist).
            # External ref source_name=mitre-attack carries the G####
            # canonical id.
            gid = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    gid = ref.get("external_id")
                    break
            if not gid:
                continue
            aliases = list(obj.get("aliases", []) or [])
            # MITRE includes the canonical name in aliases sometimes; dedupe
            name = obj.get("name", "")
            if name and name not in aliases:
                aliases = [name] + aliases
            groups_raw[obj.get("id", "")] = {
                "name": name,
                "aliases": aliases,
                "mitre_id": gid,
                "description": (obj.get("description", "") or "")[:1200],
                "techniques": [],   # filled via relationships pass below
                "deprecated": obj.get("x_mitre_deprecated", False) or obj.get("revoked", False),
            }
        elif t == "relationship" and obj.get("relationship_type") == "uses":
            rels.append((obj.get("source_ref", ""), obj.get("target_ref", "")))

    # Build a stix-id -> tid map so we can join relationships -> technique ids
    stix_to_tid = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    stix_to_tid[obj.get("id", "")] = ref.get("external_id")
                    break

    # Wire relationships: every (group-id, technique-id) "uses" pair
    for src, tgt in rels:
        if src in groups_raw and tgt in stix_to_tid:
            tid = stix_to_tid[tgt]
            if tid not in groups_raw[src]["techniques"]:
                groups_raw[src]["techniques"].append(tid)

    # Drop deprecated, sort techniques inside each group, keyed by gid
    groups = {}
    for g in groups_raw.values():
        if g["deprecated"]: continue
        g["techniques"].sort()
        groups[g["mitre_id"]] = g
    print(f"    techniques: {len(techniques)}, tactics: {len(tactics)}, groups: {len(groups)}")
    return techniques, tactics, groups


# -------- Build CIM registry from ESCU detections -----------------------------

def derive_cim_registry(detections):
    """
    Build {dataset_path: sorted_field_list} by mining real ESCU detections.

    Approach: for each detection's `search` SPL, find every
        `from datamodel=Endpoint.Processes`
    or
        `nodename="Endpoint.Processes"`
    reference, then extract every `Processes.<field>` (short-dataset prefix)
    from that detection's body.
    """
    cim = {}            # full path -> set of fields
    short_to_full = {}  # short prefix -> full path
    detection_fields_seen = 0

    for d in detections:
        spl = d.get("search", "") or ""
        if not spl:
            continue
        full_paths = set(DM_PATH_RE.findall(spl)) | set(NODENAME_RE.findall(spl))
        if not full_paths:
            continue
        for full in full_paths:
            short = full.split(".")[-1]
            cim.setdefault(full, set())
            short_to_full.setdefault(short, full)
        # Now scan all `<short>.field` patterns
        for short, field in SHORT_DS_FIELD_RE.findall(spl):
            full = short_to_full.get(short)
            if full and field not in {"as", "by", "where", "values", "count"}:
                cim[full].add(field)
                detection_fields_seen += 1

    out = {ds: sorted(fields) for ds, fields in cim.items() if fields}
    print(f"    CIM datasets seen: {len(out)}, total field-uses parsed: {detection_fields_seen}")
    return out


# -------- Build ESCU detection index ------------------------------------------

def index_detections(detections):
    """Slim copy of each detection useful for cross-referencing in generate.py."""
    out = []
    for d in detections:
        if d.get("type") not in ("TTP", "Anomaly", "Hunting", "Correlation"):
            # Skip things like "story", "investigation" YAMLs
            continue
        tags = d.get("tags") or {}
        techniques = tags.get("mitre_attack_id") or []
        if isinstance(techniques, str):
            techniques = [techniques]
        out.append({
            "id": d.get("id"),
            "name": d.get("name"),
            "type": d.get("type"),
            "description": (d.get("description") or "").strip()[:400],
            "techniques": [t for t in techniques if t],
            "kill_chain_phases": tags.get("kill_chain_phases", []) or [],
            "data_models": [
                m.group(1) for m in DM_PATH_RE.finditer(d.get("search","") or "")
            ],
            "search": d.get("search", ""),
        })
    return out


# -------- Diff & changelog ----------------------------------------------------

def changelog_summary(prev, curr):
    """Return a short markdown summary of what changed between syncs."""
    if not prev:
        return ["Initial sync."]
    lines = []
    p_cim = set(prev.get("cim_datasets", {}).keys())
    c_cim = set(curr.get("cim_datasets", {}).keys())
    if p_cim != c_cim:
        added = sorted(c_cim - p_cim)
        removed = sorted(p_cim - c_cim)
        if added: lines.append(f"CIM datasets added: {', '.join(added)}")
        if removed: lines.append(f"CIM datasets removed: {', '.join(removed)}")
    p_ttp = len(prev.get("escu_detections", []))
    c_ttp = len(curr.get("escu_detections", []))
    if p_ttp != c_ttp:
        lines.append(f"ESCU detections: {p_ttp} -> {c_ttp} ({c_ttp-p_ttp:+d})")
    p_at = len(prev.get("attack_techniques", {}))
    c_at = len(curr.get("attack_techniques", {}))
    if p_at != c_at:
        lines.append(f"ATT&CK techniques: {p_at} -> {c_at} ({c_at-p_at:+d})")
    return lines or ["No structural changes."]


def append_changelog(curr, lines):
    head = f"\n## {curr['synced_at']}\n"
    body = "\n".join(f"- {l}" for l in lines) + "\n"
    if not CHANGELOG_PATH.exists():
        CHANGELOG_PATH.write_text("# Sync Changelog\n", encoding="utf-8")
    with CHANGELOG_PATH.open("a", encoding="utf-8") as f:
        f.write(head + body)


# -------- Main ----------------------------------------------------------------

def main():
    prev = {}
    if REGISTRY_PATH.exists():
        try:
            prev = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        except Exception:
            prev = {}

    detections, macros = fetch_security_content()
    cim = derive_cim_registry(detections)
    escu_index = index_detections(detections)
    techniques, tactics, groups = fetch_attack()
    defender_queries = fetch_defender_queries()
    defender_tables, defender_actions, defender_hints = derive_defender_registry(defender_queries)

    registry = {
        "synced_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {k: v["url"] for k, v in SOURCES.items()},
        "stats": {
            "cim_datasets": len(cim),
            "escu_detections": len(escu_index),
            "attack_techniques": len(techniques),
            "attack_tactics": len(tactics),
            "attack_groups": len(groups),
            "macros": len(macros),
            "defender_tables": len(defender_tables),
            "defender_kql_blocks": len(defender_queries),
        },
        "cim_datasets": cim,
        "escu_detections": escu_index,
        "attack_techniques": techniques,
        "attack_tactics": tactics,
        "attack_groups": groups,
        "defender_tables": defender_tables,
        "defender_action_types": defender_actions,
        "defender_table_popularity": defender_hints,
    }
    REGISTRY_PATH.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    log = {
        "last_sync": registry["synced_at"],
        "registry_path": str(REGISTRY_PATH),
        "size_kb": REGISTRY_PATH.stat().st_size // 1024,
        "stats": registry["stats"],
    }
    LOG_PATH.write_text(json.dumps(log, indent=2), encoding="utf-8")

    diff = changelog_summary(prev, registry)
    append_changelog(registry, diff)

    print()
    print(f"[*] Wrote {REGISTRY_PATH} ({log['size_kb']} KB)")
    print(f"[*] Stats: {json.dumps(registry['stats'], indent=2)}")
    print(f"[*] Changelog updates:")
    for line in diff:
        print(f"      - {line}")


if __name__ == "__main__":
    main()
