#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAILED=0

echo "===== Forbidden files/directories ====="
while IFS= read -r path; do
  echo "FORBIDDEN: $path"
  FAILED=1
done < <(find . \( \
  -name '.env' -o -name '.env.backup*' -o -name '.venv' -o \
  -name '__pycache__' -o -name 'memory_db' -o -name 'results' -o \
  -name 'results_*' -o -name '*.log' -o -name '*.sqlite' -o \
  -name '*.sqlite3' -o -name '*.db' -o -name '*.tar.gz' -o \
  -name '*.zip' -o -name '*.bak*' \) -print)

echo
echo "===== Possible credentials ====="
HITS="$(grep -RInE --exclude-dir=.git --exclude='.env.example' \
  --exclude='check_release_safety.sh' --exclude='verify_public_package.py' \
  '(sk-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{20,})' \
  . 2>/dev/null || true)"
if [[ -n "$HITS" ]]; then
  echo "$HITS"
  FAILED=1
else
  echo "No obvious credentials found."
fi

echo
echo "===== Machine-specific paths ====="
PATH_HITS="$(grep -RInE --exclude-dir=.git --exclude-dir=adaptive_attacks \
  --exclude='check_release_safety.sh' --exclude='verify_public_package.py' \
  '(/Users/[^/]+/|[A-Za-z]:\\\\Users\\\\)' . 2>/dev/null || true)"
if [[ -n "$PATH_HITS" ]]; then
  echo "$PATH_HITS"
  FAILED=1
else
  echo "No machine-specific user paths found."
fi

echo
echo "===== Files over 10 MB ====="
find . -type f -size +10M -print

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "RELEASE_SAFETY_CHECK_PASS"
else
  echo "RELEASE_SAFETY_CHECK_FAILED"
  exit 1
fi
