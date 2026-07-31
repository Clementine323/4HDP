#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
MODELS="${REVISION_MODELS:-gpt-4o-mini gpt-4o llama-3.1-70b-instruct}"
STAMP="${REVISION_RUN_STAMP:-$(date +%Y%m%d_%H%M%S)}"

for model in $MODELS; do
  printf '\n%s\n' "============================================================"
  printf 'Starting revision 6/9/13 campaign for: %s\n' "$model"
  printf '%s\n' "============================================================"
  REVISION_RUN_STAMP="$STAMP" bash run_revision_6_9_13.sh "$model"
done

echo "REVISION_6_9_13_ALL_MODELS_COMPLETED: $STAMP"
