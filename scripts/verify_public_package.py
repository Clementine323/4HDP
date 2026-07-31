#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import hashlib, json, re, subprocess, sys

ROOT = Path(__file__).resolve().parents[1]
errors = []

required = [
    'README.md', 'REPRODUCIBILITY.md', 'RELEASE_SCOPE.md', 'SECURITY.md',
    'docs/ASB_ADAPTER.md', 'docs/AUDIT_PROMPT.md',
    'docs/THRESHOLDS_AND_DECISIONS.md', 'docs/SAMPLE_COMPOSITION.md',
    'docs/EXPERIMENT_PROTOCOL.md', 'docs/FAILURE_AND_BOUNDARY_CASES.md',
    'docs/OUTPUT_SCHEMA.md', 'docs/KNOWN_LIMITATIONS.md',
    'prompts/semantic_audit_prompt_template.txt',
    'fourhdp/core/shield.py', 'fourhdp/core/auditor/engine.py',
    'fourhdp/adapters/asb_adapter.py',
    'experiments/benchmarks/ASB/main_attacker_with_shield.py',
    'experiments/benchmarks/ASB/main_attacker_baseline_timing.py',
    'experiments/benchmarks/ASB/run_missing_mp_mixed_campaign.sh',
    'experiments/run_adaptive_audit.py',
]
for rel in required:
    if not (ROOT / rel).is_file():
        errors.append(f'missing required file: {rel}')

for path in ROOT.rglob('*'):
    rel = path.relative_to(ROOT)
    low = path.name.lower()
    if path.is_dir() and (low in {'.git', '.venv', '__pycache__', 'memory_db', 'results'} or low.startswith('results_')):
        errors.append(f'forbidden directory: {rel}')
    if path.is_file():
        if low == '.env' or low.startswith('.env.backup') or '.bak' in low:
            errors.append(f'forbidden private/backup file: {rel}')
        if low.endswith(('.log', '.sqlite', '.sqlite3', '.db', '.tar.gz', '.zip')):
            errors.append(f'forbidden generated/archive file: {rel}')
        if low.endswith(('_rq3.json', '_audit_events.jsonl', '_memory_events.jsonl', '_timing.json', '_traces.jsonl')):
            errors.append(f'forbidden result/trace file: {rel}')

secret_patterns = [
    re.compile(r'sk-[A-Za-z0-9_-]{16,}'),
    re.compile(r'hf_[A-Za-z0-9]{20,}'),
    re.compile(r'ghp_[A-Za-z0-9]{20,}'),
    re.compile(r'AKIA[A-Z0-9]{16}'),
    re.compile(r'AIza[A-Za-z0-9_-]{20,}'),
]
for path in ROOT.rglob('*'):
    if not path.is_file() or path.name == 'SOURCE_CHECKSUMS.sha256':
        continue
    try:
        text = path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        continue
    for pattern in secret_patterns:
        if pattern.search(text):
            errors.append(f'possible credential in {path.relative_to(ROOT)}')
    rel = path.relative_to(ROOT)
    synthetic_path = rel.parts[:2] == ('experiments', 'adaptive_attacks')
    self_check = rel in {
        Path('scripts/check_release_safety.sh'),
        Path('scripts/verify_public_package.py'),
    }
    if not synthetic_path and not self_check:
        if re.search(r'/Users/[^/]+/', text) or re.search(r'[A-Za-z]:\\\\Users\\\\', text):
            errors.append(f'machine-specific user path in {rel}')

manifest_root = ROOT / 'experiments/benchmarks/ASB/r9/manifests'
for name in ['r9_dpi_manifest.jsonl', 'r9_ipi_manifest.jsonl', 'r9_mp_manifest.jsonl', 'r9_mixed_manifest.jsonl', 'r9_pot_protocol_manifest.jsonl', 'r9_benign_revision_manifest.jsonl']:
    path = manifest_root / name
    try:
        rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
        count = sum(1 for row in rows if row.get('record_type') == 'case')
        if count != 100:
            errors.append(f'{name}: expected 100 cases, found {count}')
    except Exception as exc:
        errors.append(f'{name}: invalid JSONL: {exc}')

for name in ['MP.jsonl', 'MIXED.jsonl']:
    path = ROOT / 'experiments/benchmarks/ASB/r9/retrieval_manifests' / name
    try:
        rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
        count = sum(1 for row in rows if row.get('record_type') != 'metadata')
        if count != 100:
            errors.append(f'{name}: expected 100 retrieval records, found {count}')
    except Exception as exc:
        errors.append(f'{name}: invalid JSONL: {exc}')

for path in ROOT.rglob('*.py'):
    try:
        compile(path.read_text(encoding='utf-8'), str(path), 'exec')
    except Exception as exc:
        errors.append(f'python syntax: {path.relative_to(ROOT)}: {exc}')

for path in ROOT.rglob('*.sh'):
    proc = subprocess.run(['bash', '-n', str(path)], capture_output=True, text=True)
    if proc.returncode:
        errors.append(f'shell syntax: {path.relative_to(ROOT)}: {proc.stderr.strip()}')

checksum_path = ROOT / 'SOURCE_CHECKSUMS.sha256'
if checksum_path.exists():
    for line in checksum_path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        digest, rel = line.split('  ', 1)
        path = ROOT / rel
        if not path.is_file():
            errors.append(f'checksum target missing: {rel}')
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            errors.append(f'checksum mismatch: {rel}')

if errors:
    print('PUBLIC_PACKAGE_VERIFY_FAILED')
    for error in errors:
        print(' -', error)
    raise SystemExit(1)

print('PUBLIC_PACKAGE_VERIFY_PASS')
