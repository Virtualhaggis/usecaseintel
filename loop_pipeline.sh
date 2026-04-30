#!/bin/bash
# 2-hour rolling pipeline loop:
#   Every 20 minutes, re-fetch feeds, regenerate the site, and push if
#   anything changed. The LLM cache makes subsequent runs cheap — only
#   newly-published articles incur fresh LLM calls.
# Usage: nohup ./loop_pipeline.sh > logs/loop.log 2>&1 &
# Stops automatically after 2 hours.

set -u
cd "$(dirname "$0")"
mkdir -p logs

DEADLINE=$(($(date +%s) + 7200))   # now + 2 hours
INTERVAL=1200                       # 20 minutes between starts
ITER=1

while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  LOG="logs/loop_iter_${ITER}_$(date +%Y%m%d_%H%M%S).log"
  echo "=== iter $ITER  start $TS  log $LOG ===" | tee -a logs/loop.log

  USECASEINTEL_USE_CLAUDE_OAUTH=1 python generate.py >"$LOG" 2>&1
  RC=$?
  echo "  generate.py rc=$RC" | tee -a logs/loop.log

  # Stage exactly the regenerated outputs; don't sweep up unrelated edits
  git add intel/ catalog/ briefings/ daily_digest.md index.html 2>/dev/null

  if git diff --cached --quiet; then
    echo "  no changes this iter" | tee -a logs/loop.log
  else
    git commit -m "auto: pipeline iter $ITER ($TS)" >>logs/loop.log 2>&1
    git push >>logs/loop.log 2>&1 && echo "  pushed" | tee -a logs/loop.log \
                                  || echo "  push failed" | tee -a logs/loop.log
  fi

  ITER=$((ITER + 1))
  REMAIN=$((DEADLINE - $(date +%s)))
  if [ "$REMAIN" -le 0 ]; then break; fi
  SLEEP=$((REMAIN < INTERVAL ? REMAIN : INTERVAL))
  echo "  sleeping ${SLEEP}s before next iter" | tee -a logs/loop.log
  sleep "$SLEEP"
done

echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ) ran $((ITER-1)) iterations ===" | tee -a logs/loop.log
