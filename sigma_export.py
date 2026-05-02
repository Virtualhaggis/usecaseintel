"""Sigma rule helpers: parse, validate, and (optionally) compile to
backend platforms via pysigma.

Used in two places:
  - generate.py — runs validate_sigma() on every LLM-emitted sigma_yaml
    and on the Sigma rules shipped under sigma_rules/.
  - the cheat-sheet "compile to..." dropdown — compiles a single rule
    to KQL / SPL / Elastic on demand.

Backend availability is graceful — pysigma core is required, but each
target-platform backend (sigma-backend-microsoft365defender,
sigma-backend-azure, sigma-backend-splunk, sigma-backend-elasticsearch,
etc.) is loaded lazily. If a backend isn't installed, compile_sigma()
returns a clear error message rather than crashing.

Run as a CLI:
    python sigma_export.py <path-to-rule.yml>            # validate only
    python sigma_export.py <path-to-rule.yml> --to kql   # compile
    python sigma_export.py <path-to-rule.yml> --to spl
    python sigma_export.py <path-to-rule.yml> --to lucene
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# pysigma core — always required.
try:
    from sigma.rule import SigmaRule
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaError
    PYSIGMA_AVAILABLE = True
except Exception as e:           # pragma: no cover
    PYSIGMA_AVAILABLE = False
    SigmaRule = None             # type: ignore[assignment]
    SigmaCollection = None       # type: ignore[assignment]
    SigmaError = Exception       # type: ignore[assignment,misc]
    _IMPORT_ERROR = e


# =============================================================================
# Backend registry — tried lazily on first compile() call.
# =============================================================================

# Friendly target name → (pysigma-backend module, backend class, output format).
# Output format defaults vary per backend; pinning the most-used one here.
_BACKENDS: dict[str, tuple[str, str, str | None]] = {
    "kql":       ("sigma.backends.microsoft365defender", "KustoBackend",     "default"),
    "defender":  ("sigma.backends.microsoft365defender", "KustoBackend",     "default"),
    # Sentinel uses the same Kusto backend with a different `pipeline=`.
    "sentinel":  ("sigma.backends.microsoft365defender", "KustoBackend",     "default"),
    "spl":       ("sigma.backends.splunk",               "SplunkBackend",    "default"),
    "splunk":    ("sigma.backends.splunk",               "SplunkBackend",    "default"),
    "splunk2":   ("sigma.backends.splunk",               "SplunkSPL2Backend","default"),
    "lucene":    ("sigma.backends.elasticsearch",        "LuceneBackend",    "default"),
    "elastic":   ("sigma.backends.elasticsearch",        "LuceneBackend",    "default"),
    "qradar":    ("sigma.backends.qradar",               "QRadarBackend",    "default"),
    "powershell":("sigma.backends.powershell",           "PowerShellBackend","default"),
}


def list_backends() -> list[str]:
    """Return the friendly names of all supported targets."""
    return sorted(set(_BACKENDS.keys()))


# =============================================================================
# Validate
# =============================================================================

def validate_sigma(yaml_text: str) -> list[str]:
    """Return a list of issue strings; empty list = valid."""
    if not PYSIGMA_AVAILABLE:
        return [f"pysigma not importable: {_IMPORT_ERROR!s}"]
    if not yaml_text or not yaml_text.strip():
        return ["empty rule"]
    issues: list[str] = []
    try:
        rule = SigmaRule.from_yaml(yaml_text)
    except SigmaError as e:
        return [f"sigma parse error: {e!s}"]
    except Exception as e:
        return [f"yaml/sigma error: {e!s}"]
    # Require the conventional metadata fields that downstream tooling
    # (rule sharing, MITRE-tag indexing, etc.) depends on.
    for field in ("title", "id", "logsource", "detection"):
        if not getattr(rule, field, None):
            issues.append(f"missing required field: {field}")
    # MITRE ATT&CK tags should be present and well-formed.
    tags = [str(t) for t in (rule.tags or [])]
    if not any(t.startswith("attack.") for t in tags):
        issues.append("no MITRE ATT&CK tag (expected at least one `attack.t####`)")
    return issues


# =============================================================================
# Compile
# =============================================================================

def compile_sigma(yaml_text: str, target: str) -> tuple[str | None, str | None]:
    """Compile a Sigma rule to `target` backend.

    Returns (output, error). Exactly one of the two will be non-None.
    """
    if not PYSIGMA_AVAILABLE:
        return None, f"pysigma not installed: {_IMPORT_ERROR!s}"
    target = target.lower().strip()
    if target not in _BACKENDS:
        return None, f"unknown target '{target}'. Known: {', '.join(list_backends())}"

    module_name, class_name, _output_format = _BACKENDS[target]
    try:
        mod = __import__(module_name, fromlist=[class_name])
    except ModuleNotFoundError as e:
        # Pip-install hint by mapping module → expected package name.
        pkg_hint = {
            "sigma.backends.microsoft365defender": "pysigma-backend-microsoft365defender",
            "sigma.backends.azure":                "pysigma-backend-azure",
            "sigma.backends.splunk":               "pysigma-backend-splunk",
            "sigma.backends.elasticsearch":        "pysigma-backend-elasticsearch",
            "sigma.backends.qradar":               "pysigma-backend-qradar",
            "sigma.backends.powershell":           "pysigma-backend-powershell",
        }.get(module_name, module_name)
        return None, (f"backend '{target}' not installed - `pip install {pkg_hint}`. "
                      f"Underlying error: {e!s}")
    except Exception as e:
        return None, f"backend import error for '{target}': {e!s}"

    try:
        backend_cls = getattr(mod, class_name)
        backend = backend_cls()
        coll = SigmaCollection.from_yaml(yaml_text)
        # `convert` returns a list of strings; one entry per rule in the
        # collection. We typically have one rule per conversion call.
        out = backend.convert(coll)
        if isinstance(out, list):
            out = "\n\n".join(str(o) for o in out)
        return str(out), None
    except SigmaError as e:
        return None, f"sigma conversion error: {e!s}"
    except Exception as e:
        return None, f"backend '{target}' raised: {e!s}"


# =============================================================================
# CLI
# =============================================================================

def _cli(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("path", help="Path to a Sigma rule YAML file (or - for stdin).")
    ap.add_argument("--to", choices=list_backends(), default=None,
                    help="Compile to this backend instead of just validating.")
    args = ap.parse_args(argv)

    yaml_text = sys.stdin.read() if args.path == "-" else Path(args.path).read_text(encoding="utf-8")

    issues = validate_sigma(yaml_text)
    if issues:
        print("VALIDATION ISSUES:")
        for i in issues:
            print(f"  - {i}")
        return 1
    print("OK: valid Sigma rule")

    if args.to:
        out, err = compile_sigma(yaml_text, args.to)
        if err:
            print(f"COMPILE FAILED: {err}", file=sys.stderr)
            return 2
        print()
        print(f"--- compiled for {args.to} ---")
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
