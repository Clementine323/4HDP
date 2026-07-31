#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
DB="${R9_MEMORY_DB:-memory_db/r9/combined_attack_gpt-4o-mini_seed0_100}"
MANIFEST="${R9_MEMORY_BUILD_MANIFEST:-r9/manifests/r9_dpi_manifest.jsonl}"
RESULT_SUBDIR="memory_build/${STAMP}"
LOG="r9_memory_build_${STAMP}.log"
REPORT="r9/memory_db_verification_${STAMP}.json"

exec > >(tee "$LOG") 2>&1

echo "=================================================="
echo "R9 poisoned-memory database build"
echo "Started:  $(date)"
echo "Database: $DB"
echo "Manifest: $MANIFEST"
echo "=================================================="

python validate_r9_setup.py --manifest-dir r9/manifests --expected-cases 100

if [[ -e "$DB" ]]; then
  BACKUP="${DB}_backup_${STAMP}"
  echo "Existing database moved to: $BACKUP"
  mv "$DB" "$BACKUP"
fi
mkdir -p "$DB"

export R9_MANIFEST="$MANIFEST"
export R9_ATTACK_KIND="MEMORY_BUILD"
export R9_RANDOM_SEED=0
export R9_MAX_CASES=100
# Chroma writes are intentionally serialized for reproducibility and to avoid SQLite locking.
export R9_MAX_WORKERS=1
export R9_RESULTS_SUBDIR="$RESULT_SUBDIR"
export ASB_MEMORY_EMBEDDING_MODEL="${ASB_MEMORY_EMBEDDING_MODEL:-text-embedding-ada-002}"
unset ASB_MEMORY_TRACE_FILE || true

python main_attacker_matched.py \
  --llm_name gpt-4o-mini \
  --attacker_tools_path data/all_attack_tools.jsonl \
  --tasks_path data/agent_task.jsonl \
  --res_file memory_build.csv \
  --attack_type combined_attack \
  --direct_prompt_injection \
  --write_db \
  --database "$DB"

python verify_r9_memory_db.py \
  --database "$DB" \
  --manifest "$MANIFEST" \
  --expected-count 100 \
  --embedding-model "$ASB_MEMORY_EMBEDDING_MODEL" \
  --injection-model gpt-4o-mini \
  --attack-type combined_attack \
  --write-metadata \
  --report "$REPORT"

echo "=================================================="
echo "R9_MEMORY_DB_BUILD_COMPLETED"
echo "Finished: $(date)"
echo "Database: $DB"
echo "Report:   $REPORT"
echo "Log:      $LOG"
echo "=================================================="
