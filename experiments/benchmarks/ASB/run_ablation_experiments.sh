#!/bin/bash
set -euo pipefail

MODEL="${1:-gpt-4o-mini}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"

MODES="${FOURHDP_ABLATION_MODES:-no_static no_semantic no_history full}"
SEEDS="${FOURHDP_SEEDS:-0}"
ATTACK_CASES="${FOURHDP_ABLATION_ATTACK_CASES:-100}"
BENIGN_CASES="${FOURHDP_ABLATION_BENIGN_CASES:-100}"
STAMP="${FOURHDP_RUN_STAMP:-$(date +%Y%m%d_%H%M%S)}"
MEMORY_DB="${FOURHDP_MEMORY_DB:-memory_db/r9/combined_attack_gpt-4o-mini_seed0_100}"
export ASB_MEMORY_EMBEDDING_MODEL="${ASB_MEMORY_EMBEDDING_MODEL:-text-embedding-ada-002}"
export FOURHDP_EXPECTED_MEMORY_DB_COUNT="${FOURHDP_EXPECTED_MEMORY_DB_COUNT:-100}"

export FOURHDP_ENABLE_SAFE_FAST_PATH="${FOURHDP_ENABLE_SAFE_FAST_PATH:-0}"
export FOURHDP_STATIC_HARD_BLOCK="${FOURHDP_STATIC_HARD_BLOCK:-0}"
export FOURHDP_SINGLE_THRESHOLD="${FOURHDP_SINGLE_THRESHOLD:-0.7}"
export FOURHDP_CUMULATIVE_THRESHOLD="${FOURHDP_CUMULATIVE_THRESHOLD:-0.9}"

printf '\n================ ABLATION PLAN ================\n'
printf 'Project root:       %s\n' "$PROJECT_ROOT"
printf 'Victim model:       %s\n' "$MODEL"
printf 'Modes:              %s\n' "$MODES"
printf 'Seeds:              %s\n' "$SEEDS"
printf 'Attack cases/type:  %s\n' "$ATTACK_CASES"
printf 'Benign cases:       %s\n' "$BENIGN_CASES"
printf 'Workers:            %s\n' "${FOURHDP_MAX_WORKERS:-2}"
printf 'Safe fast path:     %s\n' "$FOURHDP_ENABLE_SAFE_FAST_PATH"
printf 'Static hard block:  %s\n' "$FOURHDP_STATIC_HARD_BLOCK"
printf '=================================================\n'

for SEED in $SEEDS; do
  export FOURHDP_RANDOM_SEED="$SEED"

  # Freeze the ASB attack sample set and official top-1 retrieval once per
  # seed. Every defense mode below receives these exact same attack inputs.
  CONTROL_DIR="results_4hdp/${MODEL}/paired_controls/${STAMP}/seed_${SEED}"
  mkdir -p "$CONTROL_DIR"
  export FOURHDP_ATTACK_CASE_MANIFEST="$CONTROL_DIR/attack_cases.jsonl"
  export ASB_MP_RETRIEVAL_MANIFEST="$CONTROL_DIR/mp_top1.jsonl"
  export ASB_MIXED_RETRIEVAL_MANIFEST="$CONTROL_DIR/mixed_top1.jsonl"

  python create_asb_case_manifest.py \
    --attacker-tools data/all_attack_tools.jsonl \
    --tasks data/agent_task.jsonl \
    --cases "$ATTACK_CASES" \
    --seed "$SEED" \
    --agent-filter "${FOURHDP_AGENT_FILTER:-financial_analyst_agent,legal_consultant_agent,medical_advisor_agent}" \
    --output "$FOURHDP_ATTACK_CASE_MANIFEST"

  python verify_r9_memory_db.py \
    --database "$MEMORY_DB" \
    --manifest "${ASB_MEMORY_BUILD_MANIFEST:-r9/manifests/r9_dpi_manifest.jsonl}" \
    --expected-count "$FOURHDP_EXPECTED_MEMORY_DB_COUNT" \
    --embedding-model "$ASB_MEMORY_EMBEDDING_MODEL" \
    --injection-model gpt-4o-mini \
    --attack-type combined_attack \
    --require-metadata \
    --report "$CONTROL_DIR/database_preflight.json"

  python freeze_asb_memory_retrieval.py \
    --database "$MEMORY_DB" \
    --case-manifest "$FOURHDP_ATTACK_CASE_MANIFEST" \
    --attacker-tools data/all_attack_tools.jsonl \
    --normal-tools data/all_normal_tools.jsonl \
    --attack-kind MP \
    --attack-type combined_attack \
    --embedding-model "$ASB_MEMORY_EMBEDDING_MODEL" \
    --require-db-metadata \
    --output "$ASB_MP_RETRIEVAL_MANIFEST"

  python freeze_asb_memory_retrieval.py \
    --database "$MEMORY_DB" \
    --case-manifest "$FOURHDP_ATTACK_CASE_MANIFEST" \
    --attacker-tools data/all_attack_tools.jsonl \
    --normal-tools data/all_normal_tools.jsonl \
    --attack-kind MIXED \
    --attack-type combined_attack \
    --embedding-model "$ASB_MEMORY_EMBEDDING_MODEL" \
    --require-db-metadata \
    --output "$ASB_MIXED_RETRIEVAL_MANIFEST"

  for ABL in $MODES; do
    echo ""
    echo "================================================="
    echo " 4HDP Ablation: $ABL | Victim: $MODEL | Seed: $SEED"
    echo "================================================="

    export FOURHDP_ABLATION="$ABL"
    export RESULTS_SUBDIR="${MODEL}/ablation/${ABL}/seed_${SEED}"

    export FOURHDP_MAX_CASES="$ATTACK_CASES"
    bash run_rq1_experiments.sh "$MODEL"

    export FOURHDP_MAX_CASES="$BENIGN_CASES"
    bash run_rq2_experiments.sh "$MODEL"

    python3 analyze_4hdp_results.py \
      --results-dir "results_4hdp/${RESULTS_SUBDIR}" \
      --output "results_4hdp/${RESULTS_SUBDIR}/summary_4hdp_metrics.csv"
  done
done

python3 summarize_ablation_results.py \
  --results-root "results_4hdp/${MODEL}/ablation" \
  --output-dir "results_4hdp/${MODEL}/ablation"

printf '\nAblation experiment complete. Summary: results_4hdp/%s/ablation/ablation_comparison.csv\n' "$MODEL"
