"""Correlate Atomic children by Sysmon ProcessGuid and calculate conservative run metrics.

Do NOT equate an ATT&CK emulation with a malicious sample or a successful kill.
"""
from __future__ import annotations
import argparse
import csv
import json
import math
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path


def flag(v):
    if isinstance(v, bool): return v
    return {'true': True, 'yes': True, '1': True,
            'false': False, 'no': False, '0': False}.get(str(v).strip().lower())


def when(v):
    if not v: return None
    try:
        return datetime.fromisoformat(str(v).strip().replace('Z', '+00:00')).astimezone(timezone.utc)
    except (ValueError, TypeError): return None


def jsonlines(path):
    p=Path(path)
    if not p.is_file(): return []
    result=[]
    for i,line in enumerate(p.read_text(encoding='utf-8-sig').splitlines(),1):
        if line.strip():
            try: result.append(json.loads(line))
            except json.JSONDecodeError as e: raise ValueError(f'{p}:{i}: {e}') from e
    return result


def rows_csv(path):
    with Path(path).open(encoding='utf-8-sig',newline='') as f:
        return list(csv.DictReader(f))


def quantile(xs,q):
    if not xs:return None
    a=sorted(xs);pos=(len(a)-1)*q;lo=math.floor(pos);hi=math.ceil(pos)
    return round(a[lo] if lo==hi else a[lo]*(hi-pos)+a[hi]*(pos-lo),3)


def matrix(cm):
    tp,fp,tn,fn=(cm[k] for k in ('TP','FP','TN','FN'))
    def div(a,b):return round(a/b,5) if b else None
    return dict(TP=tp,FP=fp,TN=tn,FN=fn,eligible=tp+fp+tn+fn,
                recall=div(tp,tp+fn),precision=div(tp,tp+fp),
                false_positive_rate=div(fp,fp+tn),accuracy=div(tp+tn,tp+fp+tn+fn))


def correlate(cases,events,audit,labels=None):
    labels_by_id = {str(r['case_id']):r for r in (labels or [])}
    starts={};children=defaultdict(list);ends=defaultdict(list)
    for e in events:
        try: eid=int(e.get('event_id',0))
        except (TypeError,ValueError):continue
        guid=str(e.get('process_guid') or '').lower().strip()
        if not guid:continue
        if eid==1:
            starts[guid]=e
            parent=str(e.get('parent_process_guid') or '').lower().strip()
            if parent:children[parent].append(guid)
        elif eid==5: ends[guid].append(e)
    audited=defaultdict(list)
    for a in audit:
        guid=str(a.get('process_guid') or '').lower().strip()
        if guid:audited[guid].append(a)
    output=[]; excluded=Counter(); slm_cm=Counter();hold_cm=Counter();latencies=[]
    completed_yes=0;completed_known=0;kill_e2e=0;real_kill=0;slm_kills=0
    for case in cases:
        cid=str(case.get('case_id','')).strip()
        if not cid:raise ValueError('Missing case_id')
        label=labels_by_id.get(cid,{})
        root=str(case.get('process_guid') or '').lower().strip()
        root_event=starts.get(root)
        descendants=[];seen={root};q=[root] if root_event else []
        while q:
            cur=q.pop(0)
            for c in children.get(cur,[]):
                if c not in seen:
                    seen.add(c);descendants.append(c);q.append(c)
        # Strict evidence: child GUID must be chained to this specific launcher GUID.
        relevant=[root]+descendants if root_event else []
        entries=[(g,r) for g in relevant for r in audited.get(g,[])]
        phase=[(g,r) for g,r in entries if str(r.get('audit_phase','')).upper()=='SLM']
        held=any(str(r.get('executed_action','')).upper()=='SUSPEND' for _,r in entries)
        approved=any(r.get('ai_is_threat') is True and str(r.get('ai_action','')).upper()=='KILL_PROCESS' and str(r.get('severity','')).upper() in ('HIGH','CRITICAL') for _,r in phase)
        positive=any(r.get('ai_is_threat') is True or str(r.get('ai_action','')).upper()=='KILL_PROCESS' for _,r in phase)
        killed=any(str(r.get('executed_action','')).upper() in ('KILL_PROCESS','TERMINATE') for _,r in entries)
        confirmed_e2e=any(g==kg and r.get('ai_is_threat') is True and str(r.get('ai_action','')).upper()=='KILL_PROCESS' and str(r.get('severity','')).upper() in ('HIGH','CRITICAL') and str(k.get('executed_action','')).upper() in ('KILL_PROCESS','TERMINATE') for g,r in phase for kg,k in entries)
        truth=str(label.get('ground_truth',case.get('ground_truth',''))).lower().strip()
        execution=flag(label.get('execution_verified',case.get('execution_verified')))
        observed=bool(root_event) and flag(case.get('sensor_observed')) is not False
        defender=flag(label.get('defender_intervened',case.get('defender_intervened')))
        # Positive classification must be reviewed with an explicit label reason.
        reason=str(label.get('label_reason','')).strip()
        error=''
        if truth not in ('benign','malicious'):error='UNREVIEWED_GROUND_TRUTH'
        elif truth=='malicious' and len(reason)<8:error='MALICIOUS_LABEL_WITHOUT_JUSTIFICATION'
        elif execution is not True:error='EXECUTION_NOT_VERIFIED'
        elif defender is not False:error='DEFENDER_INTERVENTION_OR_UNKNOWN'
        elif not observed:error='SYSMON_LAUNCHER_NOT_VERIFIED'
        elif not phase:error='NO_SLM_PHASE'
        if error:excluded[error]+=1
        else:
            slm_cm['TP' if positive and truth=='malicious' else 'FP' if positive else 'FN' if truth=='malicious' else 'TN']+=1
            hold_cm['TP' if held and truth=='malicious' else 'FP' if held else 'FN' if truth=='malicious' else 'TN']+=1
            if killed:real_kill+=1
            if approved:slm_kills+=1
            if confirmed_e2e:kill_e2e+=1
            for g,r in entries:
                if str(r.get('executed_action','')).upper()=='SUSPEND':
                    try:
                        n=float(r.get('time_to_hold_ms'))
                        if math.isfinite(n) and n>=0:latencies.append(n)
                    except (ValueError,TypeError):pass
            # Completed-before-hold requires independent completion evidence AND documented hold attempt.
            # For zero hold attempts it is undefined, not 0.
            for g in relevant:
                hold_attempts=[r for x,r in entries if x==g and (r.get('rule_id') or str(r.get('response_reason','')) in ('NOT_RUNNING','PROCESS_FINISHED_BEFORE_BLOCK')) and str(r.get('audit_phase','')).upper()=='FAST_HOLD']
                if not hold_attempts:continue
                explicit=[r.get('exited_before_hold') for r in hold_attempts if flag(r.get('exited_before_hold')) is not None]
                end_times=[when(e.get('utc')) for e in ends.get(g,[]) if when(e.get('utc'))]
                attempt_times=[when(r.get('utc')) for r in hold_attempts if when(r.get('utc'))]
                proven=bool(end_times and attempt_times and min(end_times)<min(attempt_times))
                if proven:
                    completed_known+=1;completed_yes+=1
                elif explicit and flag(explicit[-1]) is False:
                    completed_known+=1
        output.append(dict(case_id=cid,test_id=case.get('test_id',''),kind=case.get('kind',''),
                           label=truth,eligible=not bool(error),excluded_reason=error,
                           launcher_guid=root,child_process_count=len(descendants),
                           child_guids=';'.join(descendants),slm_verdict_count=len(phase),
                           slm_positive=positive if not error else 'UNKNOWN',
                           fast_hold=held if not error else 'UNKNOWN',
                           slm_kill_approved=approved if not error else 'UNKNOWN',
                           terminate_executed=killed if not error else 'UNKNOWN',
                           slm_to_terminate_verified=confirmed_e2e if not error else 'UNKNOWN',
                           defender_status=defender if defender is not None else 'UNKNOWN',
                           execution_verified=execution if execution is not None else 'UNKNOWN',
                           attack_id=case.get('attck_technique',''),
                           note='Atomic wrapper is not a malicious ground truth'))
    if len(set(r['case_id'] for r in output))!=len(output):raise ValueError('Duplicate case_id')
    return output, dict(total_cases=len(output),eligible=matrix(slm_cm)['eligible'],excluded=dict(excluded),
                        slm_detection=matrix(slm_cm),fast_hold_intervention=matrix(hold_cm),
                        time_to_hold_samples=len(latencies),p50_hold_ms=quantile(latencies,.5),p95_hold_ms=quantile(latencies,.95),
                        completed_before_hold_known=completed_known,completed_before_hold_yes=completed_yes,
                        completed_before_hold_rate=round(completed_yes/completed_known,5) if completed_known else None,
                        slm_kill_approved_cases=slm_kills,real_terminate_cases=real_kill,verified_slm_to_terminate_cases=kill_e2e,
                        warnings=['These are run-level metrics; positive ground truth requires independent behavioral verification.',
                                  'No defender intervention can be credited to DACN.',
                                  'Empty or unknown evidence is excluded, not silently counted as 0.',
                                  'Sysmon is asynchronous: no pre-execution prevention guarantee.',
                                  'Completing an Atomic runner is not evidence that its technique executed.'])


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--cases',required=True);ap.add_argument('--events',required=True)
    ap.add_argument('--audit',required=True);ap.add_argument('--labels');ap.add_argument('--out',required=True)
    a=ap.parse_args();cases=rows_csv(a.cases);labels=rows_csv(a.labels) if a.labels else None
    detail,summary=correlate(cases,jsonlines(a.events),jsonlines(a.audit),labels)
    out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    with (out/'case_results.csv').open('w',newline='',encoding='utf-8-sig') as f:
        if detail:
            writer=csv.DictWriter(f,fieldnames=list(detail[0]));writer.writeheader();writer.writerows(detail)
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# BÁO CÁO KIỂM THỬ ATOMIC E2E — DACN','',f'- Tổng lượt: **{summary["total_cases"]}**',f'- Lượt đủ điều kiện thống kê: **{summary["eligible"]}**',f'- Loại trừ: `{summary["excluded"]}`','',
           '## Chỉ số SLM (không gộp Fast Hold)','', '| TP | FP | TN | FN | Recall | FPR |', '|---:|---:|---:|---:|---:|---:|',
           '| {TP} | {FP} | {TN} | {FN} | {recall} | {false_positive_rate} |'.format(**summary['slm_detection']), '',
           '## Ngăn chặn','',f'- Fast Hold P50: {summary["p50_hold_ms"]} ms; P95: {summary["p95_hold_ms"]} ms',
           f'- Phán quyết KILL từ SLM: {summary["slm_kill_approved_cases"]}',f'- Thực thi Terminate: {summary["real_terminate_cases"]}',
           f'- Ghép đủ SLM → Terminate: {summary["verified_slm_to_terminate_cases"]}',
           f'- Completed-before-hold: {summary["completed_before_hold_yes"]}/{summary["completed_before_hold_known"]} (mẫu đủ bằng chứng)', '',
           '## Giới hạn','', '- Mẫu Atomic được gắn ATT&CK không tự động là mã độc.', '- Test bị Defender can thiệp phải tính riêng.',
           '- Để kết luận đúng về SLM, bổ sung mẫu hành vi gây hại được xác minh độc lập.']
    (out/'BAO_CAO_KET_QUA.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2,ensure_ascii=False))

if __name__=='__main__':main()
