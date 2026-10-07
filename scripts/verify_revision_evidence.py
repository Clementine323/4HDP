#!/usr/bin/env python3
"""Recompute the published revision evidence without remote model calls."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'reproducibility/revision_evidence'
problems: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        problems.append(message)


def rows(relative: str) -> list[dict[str, str]]:
    with (ROOT / relative).open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        check(bool(reader.fieldnames) and len(reader.fieldnames) == len(set(reader.fieldnames or [])),
              f'Invalid CSV header: {relative}')
        data = list(reader)
    check(all(None not in row for row in data), f'Malformed CSV row: {relative}')
    check(all(all(value is not None and value.strip() for value in row.values())
              for row in data), f'Empty CSV field: {relative}')
    return data


def integer(row: dict[str, str], key: str) -> int:
    return int(row[key])


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# The published file manifest covers every payload file, excluding itself.
manifest_path = ROOT / 'SHA256SUMS.txt'
manifest: dict[str, str] = {}
for line in manifest_path.read_text(encoding='utf-8').splitlines():
    expected, rel = line.split('  ', 1)
    check(rel not in manifest, f'Repeated manifest entry: {rel}')
    manifest[rel] = expected
all_files = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}
check(set(manifest) == all_files - {'SHA256SUMS.txt'}, 'Manifest coverage mismatch')
for rel, expected in manifest.items():
    path = ROOT / rel
    check(path.is_file() and digest(path) == expected, f'Hash mismatch: {rel}')
check(len(set(manifest.values())) == len(manifest), 'Duplicate payload file hash')

# Check the exact disclosure set for obvious sensitive or broken content.
private_patterns = {
    'credential': re.compile(r'(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|hf_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})'),
    'email': re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}'),
    'local user path': re.compile(r'(?:/' + 'Users/' + r'[^/\s]+/|[A-Za-z]:\\' + 'Users' + r'\\[^\\\s]+\\)'),
}
for rel in manifest:
    path = ROOT / rel
    body = path.read_text(encoding='utf-8')
    check('\r' not in body and '\ufffd' not in body, f'Broken text encoding/line endings: {rel}')
    for name, pattern in private_patterns.items():
        check(not pattern.search(body), f'Possible {name}: {rel}')
    if path.suffix == '.json':
        try:
            json.loads(body)
        except json.JSONDecodeError:
            check(False, f'Invalid JSON: {rel}')
    elif path.suffix == '.jsonl':
        try:
            for line in body.splitlines():
                if line.strip():
                    json.loads(line)
        except json.JSONDecodeError:
            check(False, f'Invalid JSONL: {rel}')
    elif path.suffix == '.csv':
        rows(rel)

# Table 2 adopted round: 15 standard units plus one separate 19-repeat unit.
main = rows('01_表2_主对抗实验/表2_正文采用轮_逐样本最小结果_去敏.csv')
units = rows('01_表2_主对抗实验/表2_正文采用轮_逐单元汇总.csv')
rounds = rows('01_表2_主对抗实验/表2_三轮稳定性结果汇总.csv')
check(len(main) == 1519 and len(units) == 16 and len(rounds) == 3,
      'Table 2 record/unit/round count mismatch')
main_key = lambda r: (r['统计集合'], r['受测智能体推理模型'], r['攻击类型'], r['样本ID'])
check(len({main_key(r) for r in main}) == len(main), 'Duplicate Table 2 execution key')
check(sum(r['统计集合'] == '标准1500次' for r in main) == 1500,
      'Table 2 standard denominator mismatch')
check(sum(r['统计集合'] != '标准1500次' for r in main) == 19,
      'Table 2 supplementary denominator mismatch')
check(sum(r['成功绕过'] == '1' for r in main if r['统计集合'] == '标准1500次') == 2,
      'Table 2 standard successes mismatch')
check(sum(r['成功绕过'] == '1' for r in main if r['统计集合'] != '标准1500次') == 0,
      'Table 2 supplementary successes mismatch')
grouped = defaultdict(list)
for r in main:
    grouped[(r['统计集合'], r['受测智能体推理模型'], r['攻击类型'])].append(r)
for u in units:
    key = (u['统计集合'], u['受测智能体推理模型'], u['攻击类型'])
    block = grouped[key]
    check(len(block) == integer(u, '执行数'), f'Table 2 unit count: {key}')
    check(sum(r['成功绕过'] == '1' for r in block) == integer(u, '成功绕过数'),
          f'Table 2 unit successes: {key}')
    check(sum(r['阻断类型'] == 'security' for r in block) == integer(u, '安全阻断数'),
          f'Table 2 unit security blocks: {key}')
    check(sum(r['阻断类型'] == 'audit_failure' for r in block) == integer(u, '审计失败阻断数'),
          f'Table 2 unit audit failures: {key}')
    check(sum(r['样本状态'] == 'framework_error' for r in block) == integer(u, '框架错误数'),
          f'Table 2 unit framework errors: {key}')
    check(integer(u, '合计校验') == integer(u, '执行数'), f'Table 2 unit total: {key}')
    check(all(r['源结果文件SHA256'] == u['源结果文件SHA256'] for r in block),
          f'Table 2 source hash: {key}')
    check(sorted(integer(r, '源CSV行号') for r in block) == list(range(2, len(block) + 2)),
          f'Table 2 source row coverage: {key}')
check(len(grouped) == 16, 'Table 2 unit key coverage')
check([integer(r, '标准执行成功绕过数') for r in rounds] == [0, 0, 2],
      'Three-round success counts')
check(all(integer(r, '标准执行数') == 1500 and integer(r, '补充复测执行数') == 19
          and integer(r, '审计失败阻断数') == 0 and integer(r, '框架错误数') == 0
          for r in rounds), 'Three-round denominators or errors')

audits_path = ROOT / '01_表2_主对抗实验/表2_两个成功绕过样本_去敏审计记录.jsonl'
audits = [json.loads(line) for line in audits_path.read_text().splitlines() if line.strip()]
success_ids = {r['样本ID'] for r in main if r['成功绕过'] == '1'}
check(len(audits) == 2 and {r['sample_id'] for r in audits} == success_ids,
      'Two bypass audit records do not match Table 2 successes')

# All manuscript-selected no-defense and prompt-layer comparison cells.
control = rows('01_表2_主对抗实验/表2_无防御及提示层对照_逐样本最小结果.csv')
control_summary = rows('01_表2_主对抗实验/表2_无防御及提示层对照_选定结果汇总.csv')
control_key = lambda r: (r['受测智能体推理模型'], r['攻击类型'], r['方法代码'])
check(len(control) == 4200 and len(control_summary) == 42,
      'Table 2 comparison record/unit count')
check(len({(*control_key(r), r['样本ID']) for r in control}) == len(control),
      'Duplicate Table 2 comparison execution key')
comparison_groups = defaultdict(list)
for r in control:
    comparison_groups[control_key(r)].append(r)
for s in control_summary:
    key = control_key(s)
    block = comparison_groups[key]
    check(len(block) == 100 and integer(s, '执行数') == 100 and integer(s, '有效数') == 100,
          f'Table 2 comparison denominator: {key}')
    successes = sum(r['攻击成功'] == '1' for r in block)
    check(successes == integer(s, '攻击成功数') and s['ASR'] == f'{successes:.2f}%',
          f'Table 2 comparison ASR: {key}')
    check(all(r['样本状态'] == 'valid' and r['源文件SHA256'] == s['源文件SHA256']
              for r in block), f'Table 2 comparison source/status: {key}')
    check(sorted(integer(r, '源CSV行号') for r in block) == list(range(2, 102)),
          f'Table 2 comparison source row coverage: {key}')
check(len(comparison_groups) == 42, 'Table 2 comparison unit key coverage')

# Table 3, Table 4 and the benign denominator.
ablation = rows('02_表3_消融实验/表3_消融结果摘要.csv')
check(len(ablation) == 4, 'Table 3 mode count')
for r in ablation:
    n, successes = integer(r, '对抗样本数'), integer(r, '成功绕过数')
    check(n == 500 and r['ASR'] == f'{100 * successes / n:.2f}%'
          and integer(r, '良性样本数') == 100, f'Table 3 rate: {r["配置"]}')
adaptive = rows('03_表4_自适应与反馈实验/表4_固定载荷与有限知情测试摘要.csv')
check(len(adaptive) == 4, 'Table 4 group count')
for r in adaptive:
    fixed = r['测试类型'] == '固定载荷审计压力测试'
    check(integer(r, '样本_审计数') == (152 if fixed else 72)
          and integer(r, '恶意样本数') == (118 if fixed else 72)
          and integer(r, '良性样本数') == (34 if fixed else 0),
          f'Table 4 denominator: {r["审计模型"]}/{r["测试类型"]}')
    check(integer(r, '审计绕过数') == 0, 'Table 4 bypass count')

benign = rows('06_良性400/良性400_逐样本最小结果.csv')
benign_summary = json.loads((ROOT / '06_良性400/良性400_结果摘要.json').read_text())
benign_counts = Counter(r['阻断类型'] for r in benign)
check(len(benign) == 400 and len({r['样本ID'] for r in benign}) == 400,
      'Benign-400 record count/uniqueness')
check(benign_counts == {'none': 394, 'security': 5, 'audit_failure': 1},
      'Benign-400 outcome counts')
check(benign_summary['normal_task_preservation_rate'] == 394 / 400
      and benign_summary['security_FPR_completed_audits'] == 5 / 399,
      'Benign-400 summary rates')

# Feedback trial states explain why only 133/144 repeated pairs are valid.
trials = rows('04_失败记录/反馈闭环实验_逐臂最小状态.csv')
feedback = json.loads((ROOT / '03_表4_自适应与反馈实验/反馈闭环实验_最终汇总.json').read_text())
all_group = next(r for r in feedback['groups'] if r['group'] == 'all')
trial_keys = {(r['scenario_id'], r['repeat'], r['arm']) for r in trials}
check(len(trials) == 288 and len(trial_keys) == 288, 'Feedback trial coverage')
check(Counter(r['status'] for r in trials) ==
      {'complete': 276, 'audit_failure': 2, 'attacker_error': 4, 'judge_error': 6},
      'Feedback status counts')
paired = sum(all((sid, str(rep), arm) in trial_keys and
                 any(r['scenario_id'] == sid and r['repeat'] == str(rep) and
                     r['arm'] == arm and r['status'] == 'complete' for r in trials)
                 for arm in ('feedback', 'openloop'))
             for sid in {r['scenario_id'] for r in trials} for rep in range(3))
check(paired == all_group['valid_repeated_pairs'] == 133,
      'Feedback valid repeated pairs')
check(all_group['independent_scenarios'] == 48 and all_group['audit_failures'] == 2
      and all_group['feedback_successes'] == all_group['openloop_successes'] == 0,
      'Feedback overall summary')
for key in ('audit_calls', 'attacker_calls', 'judge_calls', 'invalid_candidates'):
    check(sum(int(r[key]) for r in trials) == all_group[key], f'Feedback {key}')

if problems:
    print('REVISION_EVIDENCE_VERIFY_FAILED')
    for problem in problems:
        print(' -', problem)
    raise SystemExit(1)
print('REVISION_EVIDENCE_VERIFY_PASS')
