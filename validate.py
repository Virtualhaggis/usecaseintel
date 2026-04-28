"""
validate.py — Check that every UseCase in generate.py uses CIM datasets,
fields, and ATT&CK technique IDs that match the registry produced by sync.py.

Run:    py validate.py
Exit:   0 if no errors, 1 if there are.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
REG_PATH = ROOT / "data_sources" / "registry.json"
GEN_PATH = ROOT / "generate.py"

if not REG_PATH.exists():
    sys.exit(f"[FATAL] {REG_PATH} not found. Run sync.py first.")

registry = json.loads(REG_PATH.read_text(encoding="utf-8"))
CIM = registry["cim_datasets"]                 # full path -> [fields]  (ESCU-derived)
ATTACK = registry["attack_techniques"]          # T1234.001 -> {name, ...}

# Hand-curated CIM 8.5 spec allowlist (spec-valid but not seen in ESCU)
SPEC_PATH = ROOT / "data_sources" / "cim_spec_fields.json"
SPEC_FIELDS = {}
if SPEC_PATH.exists():
    raw = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    SPEC_FIELDS = {k: set(v) for k, v in raw.items() if not k.startswith("_")}

# Defender XDR Advanced Hunting schema allowlist (from Microsoft docs)
DEFENDER_SPEC_PATH = ROOT / "data_sources" / "defender_spec_tables.json"
DEFENDER_SPEC = {}
if DEFENDER_SPEC_PATH.exists():
    raw = json.loads(DEFENDER_SPEC_PATH.read_text(encoding="utf-8"))
    DEFENDER_SPEC = {k: set(v) for k, v in raw.items() if not k.startswith("_")}

DEFENDER_OBSERVED = {
    t: set(cols) for t, cols in registry.get("defender_tables", {}).items()
}
# Merged: union of "observed in Microsoft KQL corpus" + "in Microsoft schema docs"
DEFENDER_VALID = {}
for t in set(DEFENDER_SPEC.keys()) | set(DEFENDER_OBSERVED.keys()):
    DEFENDER_VALID[t] = DEFENDER_SPEC.get(t, set()) | DEFENDER_OBSERVED.get(t, set())

# Build merged "valid fields" view per dataset
VALID_FIELDS = {}
for ds, fields in CIM.items():
    VALID_FIELDS[ds] = set(fields) | SPEC_FIELDS.get(ds, set())
for ds, fields in SPEC_FIELDS.items():
    if ds not in VALID_FIELDS:
        VALID_FIELDS[ds] = set(fields)

# Reverse map for short prefix lookup
SHORT_TO_FULL = {p.split(".")[-1]: p for p in VALID_FIELDS.keys()}


# Load generate.py as a module --------------------------------------------------
spec = importlib.util.spec_from_file_location("gen", GEN_PATH)
gen = importlib.util.module_from_spec(spec)
sys.modules["gen"] = gen
spec.loader.exec_module(gen)

# Collect every UseCase instance defined at module level
use_cases = []
for name in dir(gen):
    obj = getattr(gen, name)
    if isinstance(obj, gen.UseCase):
        use_cases.append((name, obj))

print(f"[*] Validating {len(use_cases)} UseCase definitions in generate.py")
print(f"[*] Registry:")
print(f"      Splunk CIM datasets: {len(CIM)} (with {sum(len(v) for v in CIM.values())} field-uses)")
print(f"      Defender XDR tables: {len(DEFENDER_VALID)} "
      f"(observed in {len(DEFENDER_OBSERVED)} via Microsoft hunting corpus, "
      f"+{len(DEFENDER_SPEC) - len(set(DEFENDER_SPEC) & set(DEFENDER_OBSERVED))} from spec docs)")
print(f"      ATT&CK techniques: {len(ATTACK)}\n")

# Regexes for extraction --------------------------------------------------------
DM_RE = re.compile(r"from\s+datamodel\s*=\s*([\w.]+)", re.IGNORECASE)
NODENAME_RE = re.compile(r'nodename\s*=\s*"([\w.]+)"', re.IGNORECASE)
SHORT_FIELD_RE = re.compile(r"\b([A-Z][A-Za-z_]+)\.([a-z][\w]+)\b")
RESERVED = {"as", "by", "where", "values", "count", "earliest", "latest",
            "first_seen", "last_seen", "min", "max", "stats", "rename",
            "eval", "fields", "table", "lookup", "set", "to"}

def match_close(target, candidates, n=3):
    """Tiny similarity-by-prefix matcher for friendly error messages."""
    target_lc = target.lower()
    scored = []
    for c in candidates:
        c_lc = c.lower()
        common = 0
        for a, b in zip(c_lc, target_lc):
            if a == b: common += 1
            else: break
        scored.append((common, c))
    scored.sort(reverse=True)
    return ", ".join(c for _, c in scored[:n])


errors, warnings, infos = [], [], []

for var_name, uc in use_cases:
    spl = uc.splunk_spl or ""
    if not spl.strip():
        continue

    # 1) Validate dataset paths
    dm_paths = set(DM_RE.findall(spl)) | set(NODENAME_RE.findall(spl))
    if not dm_paths:
        infos.append(f"{var_name}: no datamodel reference (raw search — skipping CIM check)")
    for full in dm_paths:
        if full not in VALID_FIELDS:
            errors.append(f"{var_name}: datamodel `{full}` is NOT in registry or spec allowlist. "
                          f"Closest matches: {match_close(full, VALID_FIELDS.keys())}")
        else:
            short = full.split(".")[-1]
            valid = VALID_FIELDS[full]
            escu_only = set(CIM.get(full, []))
            spec_only = SPEC_FIELDS.get(full, set()) - escu_only
            for s, fld in SHORT_FIELD_RE.findall(spl):
                if s != short:
                    continue
                if fld in RESERVED:
                    continue
                if fld not in valid:
                    errors.append(
                        f"{var_name}: `{short}.{fld}` not in CIM spec or any ESCU detection for {full}."
                    )
                elif fld in spec_only:
                    infos.append(
                        f"{var_name}: `{short}.{fld}` is CIM-spec-valid but unused in ESCU "
                        f"(no production reference)."
                    )

    # 2) Validate ATT&CK technique IDs
    for tid, tname in uc.techniques:
        if tid not in ATTACK:
            errors.append(f"{var_name}: ATT&CK ID `{tid}` not in current MITRE catalog "
                          f"(deprecated or revoked?)")
        else:
            t = ATTACK[tid]
            if t.get("deprecated"):
                warnings.append(f"{var_name}: ATT&CK `{tid}` is deprecated/revoked.")

    # 3) Validate Defender KQL: tables (strict) and columns (best-effort,
    #    aware of KQL aliasing)
    kql = uc.defender_kql or ""
    if kql.strip():
        # Find every Defender XDR table mentioned anywhere in the query.
        kql_tables_seen = {t for t in DEFENDER_VALID if re.search(rf"\b{re.escape(t)}\b", kql)}
        # Aliases defined in the query — we must NOT treat these as unknown cols.
        aliased_names = set(re.findall(r"\b([A-Z][A-Za-z0-9_]+)\s*=", kql))
        # All valid columns across all referenced tables (union)
        all_valid_cols = set()
        for t in kql_tables_seen:
            all_valid_cols |= DEFENDER_VALID[t]
        # Also accept columns from any Defender table (cheap pre-built set)
        ALL_DEFENDER_COLS = set()
        for cs in DEFENDER_VALID.values():
            ALL_DEFENDER_COLS |= cs

        def is_legit(col):
            return (col in all_valid_cols
                    or col in ALL_DEFENDER_COLS
                    or col in aliased_names
                    or col in kql_tables_seen
                    or col in DEFENDER_VALID
                    or col in RESERVED
                    or col == "Timestamp")

        # Columns in `| where ColName ...` — strict check
        for col in re.findall(r"\|\s*where\s+([A-Z][A-Za-z0-9_]+)\b", kql):
            if not is_legit(col):
                warnings.append(f"{var_name} (KQL): `where {col}` — column not in any "
                                f"referenced Defender table.")
        # Columns in `| project a, b = c, d`. We only flag the LHS of bare commas
        # (skipping `LHS = RHS` aliases entirely).
        for blk in re.findall(r"\|\s*project\s+([^|]+)", kql):
            # Drop alias targets ("X = ...") and keep RHS for verification
            cleaned = re.sub(r"\b[A-Z][A-Za-z0-9_]+\s*=\s*[^,]+", "", blk)
            for col in re.findall(r"\b([A-Z][A-Za-z0-9_]+)\b", cleaned):
                if not is_legit(col):
                    warnings.append(f"{var_name} (KQL): projected `{col}` not found in any "
                                    f"referenced Defender table.")

        # Tables that look Defender-shaped but aren't in the schema = real error.
        for line in kql.splitlines():
            stripped = line.lstrip("| \t").rstrip()
            m = re.match(r"^\s*([A-Z][A-Za-z0-9]+)\s", stripped)
            if not m:
                continue
            tok = m.group(1)
            # Statement-starting tokens are tables (or `let`, `union`, etc.)
            if tok in {"let", "union", "join", "datatable", "print", "find", "search"}:
                continue
            # Skip aliases / variables defined earlier with `let X = ...`
            if tok in aliased_names:
                continue
            if tok in DEFENDER_VALID:
                continue
            # Looks like a Defender table name pattern? Then it's wrong.
            if re.match(r"(Device|Email|Identity|CloudApp|Url|Alert|AAD|Tvm|MDC)", tok):
                errors.append(f"{var_name} (KQL): table `{tok}` not in Defender XDR schema. "
                              f"Closest: {match_close(tok, DEFENDER_VALID.keys())}")
        if not kql_tables_seen:
            infos.append(f"{var_name} (KQL): no Defender XDR table reference found "
                         f"(raw / Sentinel-only query — skipping schema check)")


# -------- Report --------------------------------------------------------------

print(f"[ERRORS]  {len(errors)}")
for e in errors:
    print(f"  [E] {e}")
print()
print(f"[WARNINGS] {len(warnings)}")
for w in warnings[:50]:
    print(f"  [W] {w}")
if len(warnings) > 50:
    print(f"  …and {len(warnings)-50} more.")
print()
print(f"[INFO] {len(infos)}")
for i in infos:
    print(f"  [i] {i}")

# Save structured report
report = {
    "validated_at": registry["synced_at"],
    "use_cases_total": len(use_cases),
    "errors": errors,
    "warnings": warnings,
    "infos": infos,
}
(ROOT / "data_sources" / "validation_report.json").write_text(
    json.dumps(report, indent=2), encoding="utf-8"
)
print(f"\n[*] Report: data_sources/validation_report.json")

sys.exit(1 if errors else 0)
