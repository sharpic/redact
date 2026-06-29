#!/usr/bin/env python3
"""Compute CRAP scores per function.

CRAP = complexity² × (1 − branch_coverage)³ + complexity

Combines radon cyclomatic complexity with pytest-cov branch coverage XML.
Scores above 30 are flagged. All output is informational — this script never
exits non-zero so it does not block the build.
"""
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

WARN_THRESHOLD = 30


def crap(cc, cov_pct):
    cov = cov_pct / 100.0
    return round(cc ** 2 * (1 - cov) ** 3 + cc, 1)


# ── cyclomatic complexity via radon ───────────────────────────────────────────

proc = subprocess.run(
    [sys.executable, '-m', 'radon', 'cc', '--json', 'redact.py'],
    capture_output=True, text=True,
)
if proc.returncode != 0:
    print('radon error:', proc.stderr)
    sys.exit(0)

cc_data = json.loads(proc.stdout)

functions = []
for items in cc_data.values():
    for item in items:
        if item['type'] == 'function':
            functions.append({
                'name': item['name'],
                'start': item['lineno'],
                'end': item.get('endline', item['lineno'] + 50),
                'cc': item['complexity'],
            })
        elif item['type'] == 'class':
            for m in item.get('methods', []):
                functions.append({
                    'name': f"{item['name']}.{m['name']}",
                    'start': m['lineno'],
                    'end': m.get('endline', m['lineno'] + 50),
                    'cc': m['complexity'],
                })

# ── branch coverage per line from coverage.xml ────────────────────────────────

try:
    tree = ET.parse('coverage.xml')
except FileNotFoundError:
    print('coverage.xml not found — run pytest with --cov-branch --cov-report=xml first')
    sys.exit(0)

# lineno → (branches_total, branches_covered)
line_info: dict[int, tuple[int, int]] = {}
for line in tree.getroot().iter('line'):
    n = int(line.get('number'))
    hits = int(line.get('hits', 0))
    cond = line.get('condition-coverage', '')
    if cond:
        m = re.search(r'\((\d+)/(\d+)\)', cond)
        if m:
            line_info[n] = (int(m.group(2)), int(m.group(1)))
            continue
    line_info[n] = (1, 1 if hits else 0)

# ── per-function CRAP scores ──────────────────────────────────────────────────

rows = []
for f in functions:
    total = covered = 0
    for ln in range(f['start'], f['end'] + 1):
        if ln in line_info:
            t, c = line_info[ln]
            total += t
            covered += c
    cov_pct = (covered / total * 100) if total else 0.0
    rows.append((f['name'], f['cc'], cov_pct, crap(f['cc'], cov_pct)))

rows.sort(key=lambda r: -r[3])
high = [r for r in rows if r[3] > WARN_THRESHOLD]

# ── plain-text output for the step log ───────────────────────────────────────

col = max((len(r[0]) for r in rows), default=10)
print(f"\n{'Function':<{col}}  {'CC':>4}  {'Cov%':>6}  {'CRAP':>7}  Note")
print('─' * (col + 32))
for name, cc, cov_pct, score in rows:
    note = '⚠  consider refactoring or adding tests' if score > WARN_THRESHOLD else ''
    print(f"{name:<{col}}  {cc:>4}  {cov_pct:>6.1f}  {score:>7.1f}  {note}")
print()
if high:
    print(f'{len(high)} function(s) with CRAP > {WARN_THRESHOLD} (informational — build not blocked)')
else:
    print(f'All functions within acceptable CRAP threshold (<= {WARN_THRESHOLD})')
print()

# ── GitHub Actions step summary (appears on the run summary page) ─────────────

summary = os.environ.get('GITHUB_STEP_SUMMARY')
if summary:
    with open(summary, 'a') as f:
        f.write('## CRAP Scores\n\n')
        f.write('> CRAP = complexity² × (1 − branch_coverage)³ + complexity  '
                '— scores above 30 are flagged\n\n')
        f.write('| Function | CC | Cov% | CRAP | |\n')
        f.write('|:---|---:|---:|---:|:---|\n')
        for name, cc, cov_pct, score in rows:
            flag = '⚠' if score > WARN_THRESHOLD else ''
            f.write(f'| `{name}` | {cc} | {cov_pct:.1f} | **{score:.1f}** | {flag} |\n')
        f.write('\n')
        if high:
            f.write(f'> ⚠ {len(high)} function(s) above threshold — '
                    'informational only, build not blocked\n\n')
        else:
            f.write(f'> ✅ All functions within acceptable threshold (≤ {WARN_THRESHOLD})\n\n')
        f.write('_HTML coverage report (with per-function CRAP column) available as a build artifact._\n')
