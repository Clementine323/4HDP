#!/usr/bin/env bash
set -euo pipefail

MODEL="${1:-gpt-4o-mini}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

CASES="${FORMAL_MAX_CASES:-100}"
WORKERS="${FORMAL_MAX_WORKERS:-2}"
SEED="${FORMAL_RANDOM_SEED:-0}"
SUBDIR="${RESULTS_SUBDIR:-${MODEL}/formal/$(date +%Y%m%d_%H%M%S)}"

export R9_RESULTS_ROOT="$SCRIPT_DIR/results_matched"
export R9_RANDOM_SEED="$SEED"
export R9_MAX_CASES="$CASES"
export R9_MAX_WORKERS="$WORKERS"
export ASB_REWRITE_MODEL="${ASB_REWRITE_MODEL:-gpt-4o-mini}"
export ASB_REWRITE_MAX_ATTEMPTS="${ASB_REWRITE_MAX_ATTEMPTS:-3}"
export ASB_REWRITE_TIMEOUT_S="${ASB_REWRITE_TIMEOUT_S:-60}"

run_method() {
  local attack="$1"
  local manifest="$2"
  local method="$3"
  local defense="$4"
  shift 4

  export R9_ATTACK_KIND="$attack"
  export R9_MANIFEST="$manifest"
  export R9_RESULTS_SUBDIR="$SUBDIR/$attack/$method"

  python main_attacker_matched.py \
    --llm_name "$MODEL" \
    --attacker_tools_path data/all_attack_tools.jsonl \
    --res_file "${attack}_${method}.csv" \
    --defense_type "$defense" \
    "$@"
}

run_method DPI r9/manifests/r9_dpi_manifest.jsonl delimiter delimiters_defense \
  --tasks_path data/agent_task.jsonl \
  --attack_type combined_attack --direct_prompt_injection
run_method DPI r9/manifests/r9_dpi_manifest.jsonl paraphrase direct_paraphrase_defense \
  --tasks_path data/agent_task.jsonl \
  --attack_type combined_attack --direct_prompt_injection
run_method DPI r9/manifests/r9_dpi_manifest.jsonl instructional instructional_prevention \
  --tasks_path data/agent_task.jsonl \
  --attack_type combined_attack --direct_prompt_injection
run_method DPI r9/manifests/r9_dpi_manifest.jsonl dpr dynamic_prompt_rewriting \
  --tasks_path data/agent_task.jsonl \
  --attack_type combined_attack --direct_prompt_injection

run_method IPI r9/manifests/r9_ipi_manifest.jsonl delimiter delimiters_defense \
  --tasks_path data/agent_task.jsonl \
  --attack_type combined_attack --observation_prompt_injection
run_method IPI r9/manifests/r9_ipi_manifest.jsonl instructional instructional_prevention \
  --tasks_path data/agent_task.jsonl \
  --attack_type combined_attack --observation_prompt_injection
run_method IPI r9/manifests/r9_ipi_manifest.jsonl sandwich ob_sandwich_defense \
  --tasks_path data/agent_task.jsonl \
  --attack_type combined_attack --observation_prompt_injection

run_method POT r9/manifests/r9_pot_protocol_manifest.jsonl shuffle pot_shuffling_defense \
  --tasks_path data/agent_task_pot.jsonl \
  --attack_type combined_attack --pot_backdoor \
  --trigger "with perspicacious discernment" --task_num 2
run_method POT r9/manifests/r9_pot_protocol_manifest.jsonl paraphrase pot_paraphrase_defense \
  --tasks_path data/agent_task_pot.jsonl \
  --attack_type combined_attack --pot_backdoor \
  --trigger "with perspicacious discernment" --task_num 2

export MATCHED_RESULT_DIR="$R9_RESULTS_ROOT/$SUBDIR"
python - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["MATCHED_RESULT_DIR"])
summaries = sorted(root.rglob("*_summary.json"))
expected_cases = int(os.environ["R9_MAX_CASES"])
errors = []
if len(summaries) != 9:
    errors.append(f"expected 9 matched-defense summaries, found {len(summaries)}")
for path in summaries:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("submitted") != expected_cases:
        errors.append(f"{path}: submitted != {expected_cases}")
    if data.get("valid") != expected_cases:
        errors.append(f"{path}: valid != {expected_cases}")
    if data.get("framework_error"):
        errors.append(f"{path}: framework_error != 0")
    if data.get("rewrite_failure"):
        errors.append(f"{path}: rewrite_failure != 0")
if errors:
    raise SystemExit("MATCHED DEFENSE VALIDATION FAILED:\n" + "\n".join(errors))
print(f"MATCHED DEFENSE VALIDATION PASS: {len(summaries)} cells")
PY

printf 'Matched ASB defenses completed: %s\n' "$MATCHED_RESULT_DIR"
