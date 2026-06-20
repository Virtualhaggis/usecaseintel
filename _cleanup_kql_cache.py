"""One-time cache cleanup: apply the inline KQL autofixes (verbatim \" fix,
regex @-prefix, case ==->=~, !has_any->not(...)) to every cached UC and write
the files back, so already-cached (cache-hit) queries render clean instead of
waiting for each entry to regenerate. Idempotent; the inline gen-path fix
prevents recurrence. Lock-aware to avoid racing a live pipeline run."""
import glob, json, sys
import generate as g

if not g.acquire_pipeline_lock():
    print("[!] pipeline lock held by a live run — try again shortly.")
    sys.exit(0)
try:
    files = glob.glob("intel/.llm_uc_cache/**/*.json", recursive=True)
    changed_files = 0
    fixed_queries = 0
    for p in files:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        ucs = d.get("ucs") or []
        before = json.dumps(ucs, sort_keys=True)
        g._autofix_kql_verbatim_batch(ucs)
        g._autofix_kql_case_batch(ucs)
        g._autofix_kql_operator_batch(ucs)
        after = json.dumps(ucs, sort_keys=True)
        if after != before:
            # count touched queries
            for uc in ucs:
                for mk in ("_verbatim_autofix", "_case_autofix", "_operator_autofix"):
                    fixed_queries += len(uc.pop(mk, []) or [])
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False)
            import os
            os.replace(tmp, p)
            changed_files += 1
    print(f"[*] cache cleanup: {fixed_queries} queries fixed across {changed_files} files "
          f"(of {len(files)} scanned)")
finally:
    g.release_pipeline_lock()
