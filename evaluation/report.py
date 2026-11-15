"""Generate defensible per-case detection / false alarm / containment metrics.

Usage: python -m evaluation.report --audit data/decision_audit.jsonl --labels evaluation/labels.example.csv --out results
Labels identify Sysmon record_id. No metric is inferred from unlabeled events.
"""
import argparse
import csv
import json
from pathlib import Path


def read_audit(path):
    by_id = {}
    if not Path(path).exists():
        return by_id
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rid = str(row.get('record_id', ''))
        if not rid:
            continue
        by_id.setdefault(rid, []).append(row)
    return by_id


def summarize(audit, labels):
    counts = dict(TP=0, FP=0, TN=0, FN=0)
    rows = []
    times = []
    completion_known = 0
    completed = 0
    for lab in labels:
        rid = str(lab['record_id']).strip()
        truth = lab['ground_truth'].strip().lower()
        if truth not in {'malicious', 'benign'}:
            raise ValueError('ground_truth must be malicious or benign for record ' + rid)
        events = audit.get(rid, [])
        rule = any(e.get('executed_action') in ('SUSPEND', 'SIMULATED_HOLD') for e in events)
        blocked = any(e.get('executed_action') == 'SUSPEND' for e in events)
        detected = rule or any(e.get('ai_is_threat') is True for e in events)
        label = ('TP' if truth == 'malicious' else 'FP') if detected else ('FN' if truth == 'malicious' else 'TN')
        counts[label] += 1
        measured = next((e.get('time_to_hold_ms') for e in events if isinstance(e.get('time_to_hold_ms'), (int, float)) and e.get('executed_action') == 'SUSPEND'), None)
        if measured is not None:
            times.append(float(measured))
        finished = lab.get('completed_before_hold', '').strip().lower()
        if finished not in {'', 'true', 'false'}:
            raise ValueError('completed_before_hold must be true, false or empty')
        if finished:
            completion_known += 1
            completed += finished == 'true'
        rows.append({'record_id': rid, 'case_id': lab.get('case_id', ''), 'ground_truth': truth, 'detected': detected,
                     'confusion': label, 'actual_suspend': blocked, 'time_to_hold_ms': measured if measured is not None else 'NA',
                     'completed_before_hold': finished if finished else 'UNKNOWN'})
    def div(n, d):
        return round(n/d, 4) if d else None
    totals = {
        **counts, 'labeled_cases': len(rows),
        'detection_rate_recall': div(counts['TP'], counts['TP']+counts['FN']),
        'false_positive_rate': div(counts['FP'], counts['FP']+counts['TN']),
        'precision': div(counts['TP'], counts['TP']+counts['FP']),
        'actual_suspend_cases': sum(r['actual_suspend'] for r in rows),
        'time_to_hold_ms_average': round(sum(times)/len(times),3) if times else None,
        'time_to_hold_samples': len(times),
        'completed_before_hold_rate': div(completed, completion_known),
        'completed_before_hold_known_samples': completion_known,
        'completion_status_unknown_samples': len(rows)-completion_known,
        'notes': 'Time is Sysmon event timestamp to actual suspend, not kernel process launch to pre-execution prevention. Completion requires independent harness proof; never substitute a missing process for completed.'
    }
    return rows, totals


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--audit', default='data/decision_audit.jsonl')
    ap.add_argument('--labels', required=True)
    ap.add_argument('--out', default='results')
    args=ap.parse_args()
    with open(args.labels, encoding='utf-8-sig', newline='') as f:
        labels=list(csv.DictReader(f))
    rows, totals=summarize(read_audit(args.audit), labels)
    dest=Path(args.out); dest.mkdir(parents=True, exist_ok=True)
    with (dest/'case_results.csv').open('w', encoding='utf-8-sig', newline='') as f:
        writer=csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ['record_id','case_id','ground_truth','detected','confusion','actual_suspend','time_to_hold_ms','completed_before_hold']);writer.writeheader();writer.writerows(rows)
    (dest/'summary.json').write_text(json.dumps(totals, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(totals, ensure_ascii=False, indent=2))
if __name__=='__main__': main()
