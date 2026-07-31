#!/bin/bash
# =============================================================
# RQ2: Intent Alignment & Utility (BENIGN)
# Usage: bash run_rq2_experiments.sh [MODEL]
# Set FOURHDP_SKIP_EXISTING=1 to resume without re-running finished CSVs.
# =============================================================
set -euo pipefail

MODEL="${1:-gpt-4o-mini}"
case "$MODEL" in
    gpt-4o-mini)                 DEFAULT_SUBDIR="gpt-4o-mini" ;;
    gpt-4o)                      DEFAULT_SUBDIR="gpt-4o" ;;
    claude-3-5-sonnet-20240620)  DEFAULT_SUBDIR="claude-3-5-sonnet" ;;
    gpt-3.5-turbo)               DEFAULT_SUBDIR="gpt-3.5-turbo" ;;
    *)                           DEFAULT_SUBDIR="$MODEL" ;;
esac
SUBDIR="${RESULTS_SUBDIR:-$DEFAULT_SUBDIR}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
export RESULTS_SUBDIR="$SUBDIR"
export FOURHDP_AUDIT_MODEL="${FOURHDP_AUDIT_MODEL:-gpt-4o}"
export MODEL_NAME="$FOURHDP_AUDIT_MODEL"
export FOURHDP_ABLATION="${FOURHDP_ABLATION:-full}"
export FOURHDP_ENABLE_SAFE_FAST_PATH="${FOURHDP_ENABLE_SAFE_FAST_PATH:-0}"
export FOURHDP_STATIC_HARD_BLOCK="${FOURHDP_STATIC_HARD_BLOCK:-0}"
export FOURHDP_FLOW_SCREENING="${FOURHDP_FLOW_SCREENING:-1}"
export FOURHDP_SINGLE_THRESHOLD="${FOURHDP_SINGLE_THRESHOLD:-0.7}"
export FOURHDP_CUMULATIVE_THRESHOLD="${FOURHDP_CUMULATIVE_THRESHOLD:-0.9}"
export FOURHDP_ASB_ENFORCE_TOOL_SURFACE="${FOURHDP_ASB_ENFORCE_TOOL_SURFACE:-0}"

RESULT_DIR="results_4hdp/$SUBDIR"
mkdir -p "$RESULT_DIR"
OUTFILE="fourhdp_eval_BENIGN.csv"
BENIGN_INDEX="${FOURHDP_BENIGN_CASE_INDEX:-data/benign_case_index_v2.jsonl}"
BENIGN_MANIFEST="${ASB_BENIGN_CASE_MANIFEST:-r9/manifests/r9_benign_manifest.jsonl}"
if [[ ! -f "$BENIGN_MANIFEST" ]]; then
    echo "ERROR: required frozen benign manifest is missing: $BENIGN_MANIFEST" >&2
    exit 1
fi
export FOURHDP_CASE_MANIFEST="$BENIGN_MANIFEST"
export FOURHDP_ATTACK_KIND="BENIGN"

printf '\n==============================================\n'
printf ' RQ2: Intent Alignment & Utility\n'
printf ' Victim Model: %s\n' "$MODEL"
printf ' Results Dir:  %s/\n' "$RESULT_DIR"
printf ' Cases/run:    %s\n' "${FOURHDP_MAX_CASES:-100}"
printf ' Agent filter: %s\n' "${FOURHDP_AGENT_FILTER:-financial_analyst_agent,legal_consultant_agent,medical_advisor_agent}"
printf ' Seed:         %s\n' "${FOURHDP_RANDOM_SEED:-0}"
printf ' Workers:      %s\n' "${FOURHDP_MAX_WORKERS:-10}"
printf ' Ablation:     %s\n' "${FOURHDP_ABLATION:-full}"
printf ' Benign index: %s\n' "$BENIGN_INDEX"
printf ' Manifest:     %s\n' "$BENIGN_MANIFEST"
printf ' Auditor:      %s\n' "$FOURHDP_AUDIT_MODEL"
printf ' Skip existing:%s\n' "${FOURHDP_SKIP_EXISTING:-0}"
printf '==============================================\n'

if [[ "${FOURHDP_SKIP_EXISTING:-0}" == "1" && -s "$RESULT_DIR/$OUTFILE" && -s "$RESULT_DIR/${OUTFILE%.csv}_manifest.jsonl" ]]; then
    echo "--- [BENIGN / PNA] Skipping existing $RESULT_DIR/$OUTFILE ---"
else
    echo ""
    echo "--- [BENIGN / PNA] Starting at $(date '+%H:%M:%S') ---"
    start_time=$(date +%s)
    python main_attacker_with_shield.py \
        --attacker_tools_path "$BENIGN_INDEX" \
        --tasks_path data/agent_task.jsonl \
        --attack_type naive \
        --clean \
        --llm_name "$MODEL" \
        --res_file "$OUTFILE"
    end_time=$(date +%s)
    echo "--- [BENIGN / PNA] Finished in $((end_time - start_time))s ---"
fi

printf '\n==============================================\n'
printf ' RQ2 Experiments Completed for: %s\n' "$MODEL"
printf ' Results saved to: %s/\n' "$RESULT_DIR"
printf '==============================================\n'
