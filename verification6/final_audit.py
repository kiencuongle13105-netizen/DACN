"""Conservative evidence-grade case audit over DACN verification6 runs.

This module DOES NOT alter the EDR/SLM decision or invent malicious labels.
"""
from __future__ import annotations
import argparse,csv,json,math,statistics
from collections import defaultdict,Counter,deque
from datetime import datetime,timezone,timedelta
from pathlib import Path
from verification6.evaluate import jsonlines,rows_csv,when,flag,quantile


def d(v): return when(v)
def guid(v): return str(v or '').strip().lower()
def action(v): return str(v or '').strip().upper()
def interval(t,lo,hi): return t is not None and lo is not None and hi is not None and lo <= t <= hi

def audit_cases(cases,sysmon,audit,defender,labels=None):
    lb={r['case_id']:r for r in (labels or [])}
    starts={};children=defaultdict(list);exits=defaultdict(list)
    for event in sysmon:
        g=guid(event.get('process_guid')); t=d(event.get('utc'))
        if not g or not t: continue
        eid=str(event.get('event_id',''))
        if eid=='1':
            starts[g]=event
            p=guid(event.get('parent_process_guid'))
            if p:children[p].append(g)
        elif eid=='5': exits[g].append(event)
    per_guid=defaultdict(list)
    for event in audit:
        g=guid(event.get('process_guid'))
        if g:per_guid[g].append(event)
    results=[];problems=Counter();tot=Counter();hold_lat=[]
    cm=Counter();fast=Counter();valid=0
    for c in cases:
        cid=c['case_id'];label=lb.get(cid,{})
        root=guid(c.get('process_guid'))
        start=d(c.get('start_utc')); end=d(c.get('end_utc'))
        # A launcher can finish before its child, so allow a conservative post-run grace.
        window_end=(end or start)+timedelta(seconds=30) if (end or start) else None
        root_e=starts.get(root)
        root_valid=bool(root_e and start and interval(d(root_e.get('utc')),start-timedelta(seconds=5),window_end))
        process_guids=[root] if root_valid else []
        seen=set(process_guids); queue=deque(process_guids)
        while queue:
            parent=queue.popleft()
            for child in children.get(parent,[]):
                if child in seen:continue
                # Strict per-case association. A child outside this run's time window isn't counted.
                e=starts.get(child)
                if e and start and interval(d(e.get('utc')),start-timedelta(seconds=2),window_end):
                    seen.add(child);queue.append(child);process_guids.append(child)
        all_a=[(g,e) for g in process_guids for e in per_guid[g] if not start or not d(e.get('utc')) or d(e.get('utc'))>=start-timedelta(seconds=5)]
        slm=[(g,e) for g,e in all_a if action(e.get('audit_phase'))=='SLM']
        holds=[(g,e) for g,e in all_a if action(e.get('executed_action'))=='SUSPEND']
        resumes=[(g,e) for g,e in all_a if action(e.get('executed_action')) in ('RESUME','RESUME_PROCESS')]
        kill=[(g,e) for g,e in all_a if action(e.get('executed_action')) in ('KILL_PROCESS','TERMINATE')]
        suspicious=[(g,e) for g,e in slm if e.get('ai_is_threat') is True or action(e.get('ai_action'))=='KILL_PROCESS']
        # True positive autonomous kill requires matching GUID and real SLM approving on that GUID.
        verified_kill=any(g==kg and v.get('ai_is_threat') is True and action(v.get('ai_action'))=='KILL_PROCESS' and action(v.get('severity')) in ('HIGH','CRITICAL') and action(k.get('response_reason')) in ('POST_VERIFY_OK','SLM_VERIFIED_KILL') for g,v in slm for kg,k in kill)
        # Report a Defender overlap separately; overlap alone is not attribution.
        defender_overlaps=[]
        for e in defender:
            t=d(e.get('utc'))
            if start and t and interval(t,start-timedelta(seconds=2),window_end): defender_overlaps.append(e)
        status=flag(label.get('defender_intervened',c.get('defender_intervened')))
        if defender_overlaps:status=None # Never set False on overlapping Defender events
        truth=str(label.get('ground_truth',c.get('ground_truth',''))).lower().strip()
        verified=flag(label.get('execution_verified',c.get('execution_verified')))
        reasons=[]
        if truth not in ('benign','malicious'): reasons.append('LABEL_NOT_REVIEWED')
        if truth=='malicious' and len(str(label.get('label_reason','')).strip())<8:reasons.append('NO_MALICIOUS_LABEL_RATIONALE')
        if verified is not True:reasons.append('EXECUTION_UNVERIFIED')
        if not root_valid:reasons.append('LAUNCHER_GUID_NOT_CONFIRMED')
        if status is not False:reasons.append('DEFENDER_AMBIGUOUS_OR_ACTIVE')
        if not slm:reasons.append('NO_VERIFIED_SLM_PHASE')
        eligible=not reasons
        if eligible:
            valid+=1
            key='TP' if (suspicious and truth=='malicious') else 'FP' if suspicious else 'FN' if truth=='malicious' else 'TN'
            cm[key]+=1
            fkey='TP' if (holds and truth=='malicious') else 'FP' if holds else 'FN' if truth=='malicious' else 'TN'
            fast[fkey]+=1
        else:
            for r in reasons: problems[r]+=1
        for _,h in holds:
            try:
                latency=float(h.get('time_to_hold_ms'))
                if math.isfinite(latency) and latency>=0:hold_lat.append(latency)
            except (ValueError,TypeError):pass
        # No fabricated 0: need a documented FAST_HOLD attempt for the same GUID
        # and independent Sysmon exit strictly before attempt.
        completion='UNKNOWN'
        attempts=[(g,e) for g,e in all_a if action(e.get('audit_phase'))=='FAST_HOLD']
        if attempts:
            proven=[];refuted=[]
            for g,e in attempts:
                attempt_t=d(e.get('hold_utc') or e.get('utc'))
                exit_t=[d(x.get('utc')) for x in exits.get(g,[]) if d(x.get('utc'))]
                if attempt_t and exit_t:
                    proven.append(min(exit_t)<attempt_t)
                    refuted.append(min(exit_t)>=attempt_t)
                elif flag(e.get('exited_before_hold')) is True:
                    # Only mark yes if backed by Sysmon EID5, never just process missing.
                    pass
                elif flag(e.get('exited_before_hold')) is False and action(e.get('executed_action'))=='SUSPEND':
                    refuted.append(True)
            if any(proven): completion='YES_EID5_BEFORE_ATTEMPT'
            elif any(refuted):completion='NO_EVIDENCE_HOLD_BEFORE_EXIT'
        if completion.startswith('YES_'):tot['completed_yes']+=1;tot['completed_known']+=1
        elif completion.startswith('NO_'):tot['completed_known']+=1
        tot['cases']+=1;tot['atomic' if action(c.get('kind'))=='ATOMIC' else 'benign']+=1
        if root_valid:tot['launcher_verified']+=1
        tot['child_guids']+=max(0,len(process_guids)-1)
        tot['child_slm_events']+=sum(g!=root for g,_ in slm)
        if any(g!=root for g,_ in slm):tot['atomic_cases_with_child_slm' if action(c.get('kind'))=='ATOMIC' else 'benign_cases_with_child_slm']+=1
        tot['slm_events']+=len(slm);tot['fast_hold_actions']+=len(holds)
        tot['resume_actions']+=len(resumes);tot['terminate_actions']+=len(kill)
        if verified_kill:tot['verified_autonomous_kill_cases']+=1
        if defender_overlaps:tot['cases_with_defender_time_overlap']+=1
        if not eligible:tot['excluded_cases']+=1
        results.append(dict(case_id=cid,test_id=c.get('test_id',''),kind=c.get('kind',''),label=truth,
            eligible=eligible,exclusion_reasons=';'.join(reasons),launcher_guid=root,launcher_sysmon_verified=root_valid,
            child_process_count=max(0,len(process_guids)-1),guids=';'.join(process_guids),
            slm_event_count=len(slm),slm_child_event_count=sum(g!=root for g,_ in slm),
            slm_flagged=bool(suspicious) if slm else 'UNKNOWN',fast_hold_count=len(holds),resume_count=len(resumes),
            terminate_count=len(kill),autonomous_kill_confirmed=verified_kill,defender_overlap_events=len(defender_overlaps),
            defender_case_attribution='NOT_PROVEN' if defender_overlaps else 'NONE_IN_WINDOW',
            execution_verified=verified if verified is not None else 'UNKNOWN',completed_before_hold=completion,
            attck_technique=c.get('attck_technique',''),evidence_scope='PROCESS_TREE_WITH_SYSMON_TIME_BOUNDS' if root_valid else 'UNVERIFIED_ROOT'))
    if len({c['case_id'] for c in results})!=len(results):raise ValueError('Duplicate case IDs')
    def safe_ratio(n,dd):return round(n/dd,5) if dd else None
    verdict={'TP':cm['TP'],'FP':cm['FP'],'TN':cm['TN'],'FN':cm['FN'],
             'precision':safe_ratio(cm['TP'],cm['TP']+cm['FP']),
             'recall':safe_ratio(cm['TP'],cm['TP']+cm['FN']),
             'false_positive_rate':safe_ratio(cm['FP'],cm['FP']+cm['TN'])}
    summary=dict(total_cases=tot['cases'],atomic_cases=tot['atomic'],benign_cases=tot['benign'],
        launcher_sysmon_verified=tot['launcher_verified'],child_guids=tot['child_guids'],
        slm_events_in_cases=tot['slm_events'],slm_events_on_children=tot['child_slm_events'],
        atomic_cases_with_child_slm=tot['atomic_cases_with_child_slm'],
        fast_hold_actions=tot['fast_hold_actions'],resume_actions=tot['resume_actions'],
        terminate_actions=tot['terminate_actions'],verified_autonomous_kill_cases=tot['verified_autonomous_kill_cases'],
        defender_overlap_cases=tot['cases_with_defender_time_overlap'],
        sysmon_eid1_count=sum(str(x.get('event_id'))=='1' for x in sysmon),
        sysmon_eid5_count=sum(str(x.get('event_id'))=='5' for x in sysmon),
        hold_p50_ms=quantile(hold_lat,.5),hold_p95_ms=quantile(hold_lat,.95),hold_samples=len(hold_lat),
        completed_before_hold_yes=tot['completed_yes'],completed_before_hold_known=tot['completed_known'],
        completed_before_hold_rate=safe_ratio(tot['completed_yes'],tot['completed_known']),
        slm_detection=verdict,fast_hold_confusion_matrix=dict(fast),eligible_cases=valid,
        excluded_cases=tot['excluded_cases'],exclusion_reasons=dict(problems),
        caveats=['A successful Atomic launcher is not verified malicious activity.',
                 'Defender temporal overlap is not causal attribution. Review Defender event details.',
                 'No Sysmon EID5 means completed-before-hold often cannot be measured.',
                 'No authentic SLM kill means autonomous elimination remains unproven.'])
    return results,summary


def main():
    p=argparse.ArgumentParser()
    for key in ('cases','events','audit','defender','labels','out'):p.add_argument('--'+key,required=key not in ('labels','defender'))
    a=p.parse_args()
    rows,summary=audit_cases(rows_csv(a.cases),jsonlines(a.events),jsonlines(a.audit),jsonlines(a.defender) if a.defender else [],rows_csv(a.labels) if a.labels else None)
    out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    with (out/'case_evidence.csv').open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else ['case_id']);writer.writeheader();writer.writerows(rows)
    (out/'summary_final.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# BÁO CÁO NGHIỆM THU DACN — BẰNG CHỨNG E2E','',
        f'- Tổng lượt: **{summary["total_cases"]}**; đủ điều kiện tính nhãn: **{summary["eligible_cases"]}**',
        f'- Sự kiện Sysmon EID1: **{summary["sysmon_eid1_count"]}**; EID5: **{summary["sysmon_eid5_count"]}**',
        f'- ProcessGuid con: **{summary["child_guids"]}**; sự kiện SLM trên tiến trình con: **{summary["slm_events_on_children"]}**',
        f'- SUSPEND: **{summary["fast_hold_actions"]}**; RESUME: **{summary["resume_actions"]}**; TERMINATE: **{summary["terminate_actions"]}**',
        f'- SLM → Terminate xác minh: **{summary["verified_autonomous_kill_cases"]}**',
        f'- Thời gian Hold P50/P95: **{summary["hold_p50_ms"]} / {summary["hold_p95_ms"]} ms**',
        f'- Hoàn tất trước Hold: **{summary["completed_before_hold_yes"]}/{summary["completed_before_hold_known"]}**; tỷ lệ: **{summary["completed_before_hold_rate"]}**',
        f'- Lượt trùng thời gian với Defender: **{summary["defender_overlap_cases"]}** (chưa chứng minh can thiệp vào lượt)',
        '', '## Confusion matrix SLM', '', '| TP | FP | TN | FN | Recall | FPR |', '|---:|---:|---:|---:|---:|---:|',
        '| {TP} | {FP} | {TN} | {FN} | {recall} | {false_positive_rate} |'.format(**summary['slm_detection']),
        '', '## Giới hạn cần công bố', '', *['- '+x for x in summary['caveats']]]
    (out/'BAO_CAO_NGHIEM_THU_CUOI.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
