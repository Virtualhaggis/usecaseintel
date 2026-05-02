"""KQL schema validator — flag fields that don't exist in canonical Defender tables.

Loads `data_sources/defender_spec_tables.json` and exposes a single
function:

    validate_kql(kql) -> list[Issue]

An Issue is a dict like::

    {"kind": "unknown_field", "field": "RemoteAddress",
     "tables_in_scope": ["DeviceNetworkEvents"],
     "suggestion": "RemoteIP"}

The parser is heuristic, not a real grammar — it catches obvious
field-name typos and wrong-table mistakes (e.g. using `EmailEvents`
columns inside a `DeviceProcessEvents` query) while keeping false
positives low. A KQL grammar would catch more, but for production
gating against the LLM output, the heuristic is enough.

Used in two places:
  - generate.py — runs after every LLM UC generation; attaches
    issues to the UC dict.
  - validate_kql_knowledge.py --score — corpus-wide scorer.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).parent
DEFENDER_SCHEMA_PATH = ROOT / "data_sources" / "defender_spec_tables.json"
SENTINEL_SCHEMA_PATH = ROOT / "data_sources" / "sentinel_spec_tables.json"


# =============================================================================
# Canonical schema load — Defender + Sentinel
# =============================================================================

def _load_schema_file(path: Path) -> dict[str, list[str]]:
    """Return {TableName: [Column, ...]} — drops `_comment`/`_source` meta keys."""
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, list)}


DEFENDER_SCHEMA = _load_schema_file(DEFENDER_SCHEMA_PATH)
SENTINEL_SCHEMA = _load_schema_file(SENTINEL_SCHEMA_PATH)


def _merge(*schemas: dict[str, list[str]]) -> dict[str, list[str]]:
    """Combine schemas by taking the UNION of columns per table.
    A table that appears in multiple platforms (e.g. `IdentityInfo`) gets
    every column known anywhere — the cost is some missed cross-platform
    column-mismatch checks; the gain is no false positives when the
    validator can't tell which platform a query targets."""
    out: dict[str, list[str]] = {}
    for s in schemas:
        for table, cols in s.items():
            seen = set(out.setdefault(table, []))
            for c in cols:
                if c not in seen:
                    out[table].append(c)
                    seen.add(c)
    return out


SCHEMA = _merge(DEFENDER_SCHEMA, SENTINEL_SCHEMA)
ALL_TABLES = set(SCHEMA.keys())

# Per-platform owners — used for richer error messages.
PLATFORM_TABLES: dict[str, set[str]] = {
    "defender": set(DEFENDER_SCHEMA.keys()),
    "sentinel": set(SENTINEL_SCHEMA.keys()),
}


# =============================================================================
# KQL identifiers we never want to flag — keywords, operators, scalar funcs
# =============================================================================

# Operators / clause keywords — case-insensitive match
KQL_KEYWORDS = {
    # statement-level
    "let", "set", "print", "tabular",
    # tabular operators
    "where", "project", "project-away", "project-rename", "project-reorder",
    "project-keep", "extend", "summarize", "order", "sort", "top",
    "take", "limit", "distinct", "count", "sample",
    "join", "union", "lookup", "mv-expand", "mv-apply", "search", "find",
    "render", "evaluate", "facet", "fork", "as", "consume",
    "datatable", "externaldata",
    # in `summarize ... by`, `order by`, etc.
    "by", "asc", "desc", "nulls", "first", "last",
    # join types
    "kind", "inner", "innerunique", "leftouter", "rightouter", "fullouter",
    "leftsemi", "rightsemi", "leftanti", "rightanti", "anti", "semi",
    # boolean / control
    "and", "or", "not", "true", "false", "null", "isfuzzy", "withsource",
    "format", "ignorefirstrecord", "ingestionmapping",
    # comparison/operator words (already lowercase but be safe)
    "between", "in", "has", "has_any", "has_all", "hasprefix", "hassuffix",
    "contains", "startswith", "endswith", "matches", "regex",
    "step", "from", "to", "default", "on",
}

# Scalar / aggregation functions — anything that appears as `Name(`
KQL_FUNCTIONS = {
    # time
    "ago", "now", "datetime", "totimespan", "todatetime", "dayofweek",
    "dayofmonth", "dayofyear", "startofday", "endofday", "startofweek",
    "startofmonth", "startofyear", "format_datetime", "format_timespan",
    "datetime_diff", "datetime_add", "bin", "bin_at", "make_datetime",
    "make_timespan", "monthofyear", "weekofyear", "hourofday", "getmonth",
    "getyear",
    # type / cast
    "tostring", "toint", "tolong", "toreal", "todouble", "tobool",
    "todynamic", "todatetime", "totimespan", "tobool", "toscalar",
    "parse_json", "parse_xml", "parse_url", "parse_urlquery",
    "parse_user_agent", "parse_path", "parse_csv", "parse_ipv4_mask",
    "extract", "extract_all", "extract_json",
    # string
    "strcat", "strcat_array", "strlen", "substring", "tolower", "toupper",
    "trim", "trim_start", "trim_end", "split", "replace", "replace_string",
    "replace_strings", "replace_regex", "reverse", "indexof",
    "countof", "format_bytes",
    # math
    "abs", "round", "ceiling", "floor", "exp", "log", "log10", "log2",
    "sqrt", "pow", "min_of", "max_of",
    # null / empty
    "isempty", "isnotempty", "isnull", "isnotnull", "iif", "iff", "case",
    "coalesce",
    # ip
    "ipv4_is_in_range", "ipv4_is_in_any_range", "ipv4_is_private",
    "ipv4_compare", "parse_ipv4", "format_ipv4", "ipv4_is_match",
    "ipv6_is_match", "geo_info_from_ip_address",
    # array / set
    "array_length", "array_index_of", "array_slice", "array_concat",
    "array_split", "array_iif", "set_difference", "set_intersect",
    "set_union", "bag_keys", "bag_merge", "bag_pack", "bag_unpack",
    "bag_remove_keys", "make_list", "make_set", "any", "arg_min", "arg_max",
    "min", "max", "sum", "avg", "stdev", "variance", "percentile",
    "percentiles", "dcount", "count_distinct", "countif", "sumif",
    "avgif", "minif", "maxif", "dcountif", "make_listif", "make_setif",
    "anyif", "argmin", "argmax", "row_number", "row_cumsum", "next",
    "prev", "dense_rank",
    # base64 / hash
    "base64_encodestring", "base64_encodearray_tostring",
    "base64_decodestring", "base64_decode_tostring",
    "base64_decode_toarray", "hash", "hash_md5", "hash_sha1",
    "hash_sha256",
    # regex / search
    "matches", "matches_regex",
    # series
    "series_decompose_anomalies", "series_decompose", "series_decompose_forecast",
    "series_outliers", "series_periods_detect", "series_fit_line",
    "series_stats", "series_seasonal", "series_iir", "series_fir",
    "make_series",
    # logical/control / misc
    "iif", "iff", "case", "tostring", "trim", "rand", "format_string",
    "column_ifexists", "ifexists", "row_window_session", "row_rank",
    # render
    "render",
}

# Identifiers that are operators glued onto field names (e.g. `RemoteIP in (...)`).
# We never flag these; they aren't fields.
KQL_TOKEN_OPERATORS = {
    "has_cs", "has_any", "has_all", "hasprefix_cs", "hassuffix_cs",
    "contains_cs", "startswith_cs", "endswith_cs", "in", "in~", "!in",
    "!in~", "!has", "!has_cs", "!contains", "!contains_cs",
    "!startswith", "!endswith", "matches",
}

# Anything in this set, when used after `.`, is fine — it's a JSON / dynamic
# property access, not a table column reference. We strip these.
JSON_PROPERTY_PASS = True


# =============================================================================
# Strip strings & comments before parsing
# =============================================================================

# Path-friendly: treat ALL string types as ending at the first matching
# unescaped quote, regardless of `\` content. KQL queries in security
# contexts almost always use `\` as a literal path separator, not as an
# escape character. Trying to honour `\"` escapes leads to backslashed
# paths being misparsed as multi-string concatenations.
_STRING_LITERAL_RE = re.compile(
    r'@?h?"[^"]*"'              # double-quoted (verbatim/obfuscated prefix optional)
    r"|@?h?'[^']*'",            # single-quoted
)
_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_noise(kql: str) -> str:
    """Replace string literals + comments with spaces of equal length so
    column-position-based heuristics still work, but their contents are
    invisible to the identifier scanner."""
    def blank(m: re.Match) -> str:
        return " " * (m.end() - m.start())
    s = _COMMENT_RE.sub(blank, kql)
    s = _STRING_LITERAL_RE.sub(blank, s)
    return s


# =============================================================================
# Table extraction
# =============================================================================

# A table reference is any canonical-table-name token in the cleaned
# (string/comment-stripped) query body. Permissive on purpose — once a
# table is named anywhere (top-level, inside `let X = T | ...`, inside
# `union (...)` or `join (T | ...)`), its columns are in scope.
_TABLE_REF_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]+)\b")


def _find_tables(kql: str) -> set[str]:
    """Return the set of canonical Defender tables referenced in `kql`.

    `kql` should be the noise-stripped form (strings + comments
    blanked out) so we don't false-match inside string literals.
    """
    found: set[str] = set()
    for m in _TABLE_REF_RE.finditer(kql):
        ident = m.group(1)
        if ident in ALL_TABLES:
            found.add(ident)
    return found


# =============================================================================
# Local-binding extraction (let / extend / project-as / summarize-as / mv-expand-as)
# =============================================================================

# `let Name = ...;`  or  `let Name = (\n ... );`  — we only need the LHS.
_LET_RE = re.compile(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", re.IGNORECASE)

# Inside `extend`, `project`, `summarize`, `join (..) on`, `mv-expand`, etc.,
# the pattern `Name =` defines a new local field.
# Exclude operators `==`, `=~` (the second char after `=` must not be `=` or `~`).
_LOCAL_DEF_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s*=(?![=~])\s*",  # NewName = ... (not == or =~)
)

# `summarize ... by Group1, Group2` — the LHS of `by` is the agg list (which
# defines new aliases), the RHS is the group-by columns (which must already
# exist or be defined).  We don't try to special-case here; the `Name =`
# rule above already captures the agg LHS, and the group-by names will be
# checked as field references via the generic identifier scan.

# `mv-expand Name` and `mv-expand todynamic(Name)` — when the name is reused
# downstream, it remains the same column.  Nothing new to track.


def _local_definitions(kql: str) -> set[str]:
    """Identifiers introduced by `let` / `extend` / `project N=` / etc.
    These are never table fields and must not be flagged."""
    out: set[str] = set()
    out.update(m.group(1) for m in _LET_RE.finditer(kql))
    out.update(m.group(1) for m in _LOCAL_DEF_RE.finditer(kql))
    return out


# =============================================================================
# Identifier extraction
# =============================================================================

# A "candidate field" is a capitalised identifier appearing as a bare token
# in the stripped query body. We exclude:
#  - identifiers preceded by `.` (member access on dynamic/JSON values)
#  - identifiers immediately followed by `(` (function calls)
#  - identifiers that are keywords / scalar functions / token-operators
#  - identifiers that are themselves table names
#  - identifiers in `let` LHS / `extend` LHS / etc.
_IDENT_RE = re.compile(r"(?<![A-Za-z0-9_\.\$])([A-Z][A-Za-z0-9_]+)\b")


def _candidate_fields(kql_clean: str) -> list[tuple[str, int]]:
    """Yield (identifier, char_position) for every candidate field reference.

    `kql_clean` should have been through `_strip_noise` already.
    """
    out: list[tuple[str, int]] = []
    for m in _IDENT_RE.finditer(kql_clean):
        ident = m.group(1)
        end = m.end()
        # function call → skip
        if end < len(kql_clean) and kql_clean[end] == "(":
            continue
        out.append((ident, m.start()))
    return out


# =============================================================================
# Validation
# =============================================================================

class Issue(dict):
    """Lightweight dict subclass so callers can json-serialise directly."""


def _suggestion_for(field: str, candidates: set[str]) -> str | None:
    """Return the most plausible canonical field if `field` is a near-miss.

    Uses difflib to rank by overall string similarity. Deterministic.
    """
    if not candidates:
        return None
    import difflib
    matches = difflib.get_close_matches(field, list(candidates), n=1, cutoff=0.6)
    return matches[0] if matches else None


def validate_kql(kql: str) -> list[Issue]:
    """Validate `kql` against the canonical Defender schema.

    Returns a list of Issues. Empty list = clean.
    """
    if not kql or not SCHEMA:
        return []

    clean = _strip_noise(kql)

    tables = _find_tables(clean)
    locals_ = _local_definitions(clean)
    fields = _candidate_fields(clean)

    # Build the union of all canonical columns across referenced tables.
    valid_fields: set[str] = set()
    for t in tables:
        valid_fields.update(SCHEMA.get(t, []))

    # Join-rename artefacts: when two joined tables share a column name,
    # the right-hand instance gets a numeric suffix (`Timestamp1`,
    # `DeviceId1`, etc.). Accept up to 9 chained joins.
    if "join" in clean.lower():
        for col in list(valid_fields):
            for i in range(1, 10):
                valid_fields.add(f"{col}{i}")

    # Fields that are valid in *some* canonical table but not in any of the
    # referenced ones — likely a wrong-table mistake.
    cross_table_lookup: dict[str, list[str]] = {}
    for tname, cols in SCHEMA.items():
        for c in cols:
            cross_table_lookup.setdefault(c, []).append(tname)

    issues: list[Issue] = []
    seen_pairs: set[tuple[str, frozenset[str]]] = set()

    for ident, _pos in fields:
        if ident in ALL_TABLES:
            continue
        if ident in locals_:
            continue
        if ident.lower() in KQL_KEYWORDS:
            continue
        if ident.lower() in KQL_FUNCTIONS:
            continue
        if ident.lower() in KQL_TOKEN_OPERATORS:
            continue
        if ident in valid_fields:
            continue

        key = (ident, frozenset(tables))
        if key in seen_pairs:
            continue
        seen_pairs.add(key)

        canonical_owners = cross_table_lookup.get(ident)
        if canonical_owners and tables and not any(t in tables for t in canonical_owners):
            issues.append(Issue(
                kind="wrong_table",
                field=ident,
                tables_in_scope=sorted(tables),
                exists_on=canonical_owners,
                message=(
                    f"`{ident}` is not a column of "
                    f"{', '.join(sorted(tables))}; it does exist on "
                    f"{', '.join(canonical_owners)}."
                ),
            ))
        elif tables and not canonical_owners:
            sugg = _suggestion_for(ident, valid_fields)
            issues.append(Issue(
                kind="unknown_field",
                field=ident,
                tables_in_scope=sorted(tables),
                suggestion=sugg,
                message=(
                    f"`{ident}` is not a canonical column of "
                    f"{', '.join(sorted(tables))}."
                    + (f" Did you mean `{sugg}`?" if sugg else "")
                ),
            ))
        elif not tables:
            # Query references no canonical table — out of scope.
            return []

    return issues


# =============================================================================
# Convenience: pretty-print issues
# =============================================================================

def format_issues(issues: list[Issue]) -> str:
    if not issues:
        return "(no field issues)"
    return "\n".join(f"  - {i['kind']}: {i['message']}" for i in issues)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python kql_schema_validator.py <file.kql | -->")
        sys.exit(2)
    if sys.argv[1] == "-":
        kql = sys.stdin.read()
    else:
        kql = Path(sys.argv[1]).read_text(encoding="utf-8")
    found = validate_kql(kql)
    if not found:
        print("CLEAN — no field issues.")
        sys.exit(0)
    print(f"FOUND {len(found)} issue(s):")
    print(format_issues(found))
    sys.exit(1)
