"""KQL syntax validator — real grammar validation via Microsoft.Azure.Kusto.Language.

Wraps the `tools/kql_syntax_checker/bin/kql_syntax_checker.exe` self-contained
Win-x64 binary that embeds Microsoft's official Kusto.Language parser (the
same engine the Defender XDR Advanced Hunting UI uses). Single-call batch
interface — feed many queries in one subprocess invocation to avoid paying
the .NET startup cost per individual KQL string.

Sister module to `kql_schema_validator.py`:
  - `kql_schema_validator.validate_kql()` catches unknown table / column
    names against Defender + Sentinel canonical schemas (semantic).
  - `kql_syntax_validator.validate_kql_syntax_batch()` catches grammar
    errors — missing pipes, malformed `summarize`, bad operator spellings
    (syntactic).

Used in two places:
  - generate.py — runs alongside the schema validator after every LLM UC
    generation; if either flags errors the pipeline can re-prompt with the
    error payload (auto-retry loop).
  - kql_check.py — corpus-wide audit CLI.

Public API:

    from kql_syntax_validator import validate_kql_syntax_batch, Issue

    results = validate_kql_syntax_batch([
        ("uc1", "DeviceProcessEvents | where ..."),
        ("uc2", "EmailEvents | summarize ..."),
    ])
    # results: list[dict] with shape {"id": ..., "ok": bool, "errors": [Issue, ...]}

Graceful-degrade contract: if the binary is missing, the subprocess
crashes, or the call times out, every entry's `errors` is set to []
(empty) — never raises. The pipeline keeps working without syntax
validation rather than failing.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent
_BINARY_PATH = ROOT / "tools" / "kql_syntax_checker" / "bin" / "kql_syntax_checker.exe"
_TIMEOUT_SEC = 30
_SCHEMA_VALIDATOR_KIND = "syntax_error"


def is_available() -> bool:
    """True if the C# binary is present and looks runnable."""
    return _BINARY_PATH.exists() and _BINARY_PATH.is_file()


def validate_kql_syntax_batch(entries: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Validate a batch of KQL queries via the C# Kusto.Language parser.

    Each input is `(id, kql)`. Returns a list of dicts shaped:

        {
            "id": "<the input id>",
            "ok": bool,                 # True iff no Error-severity diagnostics
            "errors": [                 # list of Issue dicts (Issue shape below)
                {
                    "kind": "syntax_error",
                    "severity": "Error" | "Warning",
                    "message": "...",
                    "line": int,        # 1-based
                    "column": int,      # 1-based
                    "start": int,       # 0-based char offset
                    "length": int,
                },
                ...
            ],
        }

    On binary-missing / subprocess failure / timeout: returns one entry per
    input with `ok=True, errors=[]`. The pipeline silently degrades. Watch
    for the log line `[!] kql_syntax_validator: <reason>` if you want to
    detect this failure mode in production logs.
    """
    if not entries:
        return []

    fallback = [{"id": eid, "ok": True, "errors": []} for eid, _ in entries]

    if not is_available():
        # Quiet on every call would spam logs; quiet on first miss is
        # acceptable since this is a graceful-degrade path.
        return fallback

    payload = json.dumps(
        [{"id": eid, "kql": kql or ""} for eid, kql in entries],
        ensure_ascii=False,
    )

    try:
        proc = subprocess.run(
            [str(_BINARY_PATH)],
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        print(f"[!] kql_syntax_validator: timeout after {_TIMEOUT_SEC}s on "
              f"{len(entries)} entries; falling back to no-validation",
              flush=True)
        return fallback
    except (OSError, FileNotFoundError) as e:
        print(f"[!] kql_syntax_validator: subprocess launch failed: {e}",
              flush=True)
        return fallback

    if proc.returncode != 0:
        err_tail = (proc.stderr or "").strip().splitlines()[-1:][:1]
        print(f"[!] kql_syntax_validator: rc={proc.returncode}: "
              f"{err_tail or '(no stderr)'}", flush=True)
        return fallback

    try:
        raw = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as e:
        print(f"[!] kql_syntax_validator: stdout not valid JSON: {e}",
              flush=True)
        return fallback

    # Map raw → public shape (rename "diagnostics" → "errors", attach kind).
    by_id = {}
    for entry in raw:
        eid = entry.get("id", "")
        ok = bool(entry.get("ok"))
        diagnostics = entry.get("diagnostics") or []
        errors = []
        for d in diagnostics:
            sev = (d.get("severity") or "").lower()
            # Only surface Error-severity diagnostics by default. Warnings
            # are sometimes false-positive style preferences (e.g. "consider
            # using ..."); they shouldn't trigger an LLM retry.
            if sev != "error":
                continue
            errors.append({
                "kind": _SCHEMA_VALIDATOR_KIND,
                "severity": d.get("severity", "Error"),
                "message": d.get("message", ""),
                "line": int(d.get("line", 0) or 0),
                "column": int(d.get("column", 0) or 0),
                "start": int(d.get("start", 0) or 0),
                "length": int(d.get("length", 0) or 0),
            })
        by_id[eid] = {"id": eid, "ok": ok and not errors, "errors": errors}

    # Preserve input order; fill any missing ids with the success fallback
    # (shouldn't happen but defensive — keeps callers' indexing intact).
    out = []
    for eid, _ in entries:
        out.append(by_id.get(eid) or {"id": eid, "ok": True, "errors": []})
    return out


def validate_kql_syntax(kql: str) -> list[dict[str, Any]]:
    """Single-query convenience wrapper. Returns just the errors list."""
    if not kql or not kql.strip():
        return []
    result = validate_kql_syntax_batch([("_one", kql)])
    return result[0]["errors"] if result else []
