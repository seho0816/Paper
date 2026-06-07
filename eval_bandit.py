"""eval_bandit.py — 비교군 ①: Bandit (SAST)"""
import os, re, time, json, subprocess
from config import TEST_DIR, RESULT_DIR, MODEL_BANDIT
from utils.scoring import ground_truth, score
from utils.metrics import compute
from utils.storage import make_row, save_report, save_csv

LABEL = MODEL_BANDIT

def _run(path):
    start = time.time()
    found = []
    try:
        r = subprocess.run(['bandit', '-r', path, '-f', 'json', '-q'],
                           capture_output=True, text=True, timeout=60)
        for issue in json.loads(r.stdout).get('results', []):
            cwe = issue.get('issue_cwe', {})
            if 'id' in cwe:
                c = f"CWE-{cwe['id']}"
                if c not in found: found.append(c)
    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(f"  Bandit 오류: {e}")
    return found, round(time.time() - start, 2)

def main():
    print(f"=== [{LABEL}] 평가 시작 ===\n")
    files = sorted(f for f in os.listdir(TEST_DIR) if f.endswith('.py'))
    import argparse as _ap
    # ── 실행 옵션 ──────────────────────────────────────────────
    # 전체 평가:           python eval_bandit.py
    # 앞에서 N개만:        python eval_bandit.py --limit 10
    # 무작위 N쌍 샘플:     python eval_bandit.py --sample 5
    # ────────────────────────────────────────────────────────────
    _p = _ap.ArgumentParser()
    _p.add_argument('--limit',  type=int, default=0)
    _p.add_argument('--sample', type=int, default=0)
    _args = _p.parse_args()
    if not files: print("파일 없음"); return
    import random as _rnd
    if _args.sample > 0:
        test_fs = [f for f in files if re.search(r'test\d*\.py$', f, re.I)]
        chosen  = set(_rnd.sample(test_fs, min(_args.sample, len(test_fs))))
        stems   = {re.sub(r'(?:test|patch)(\d*)\.py$', r'\1', f, re.I) for f in chosen}
        files   = sorted(f for f in files if re.sub(r'(?:test|patch)(\d*)\.py$', r'\1', f, re.I) in stems)
    elif _args.limit > 0:
        files = files[:_args.limit]

    total = len(files); correct = 0; total_time = 0.0
    logs = []; csv_data = []

    for idx, fname in enumerate(files, 1):
        path = os.path.join(TEST_DIR, fname)
        gt   = ground_truth(fname)
        gt_s = "/".join(gt)
        print(f"  [{idx:02d}/{total}] {fname}", end=" ... ", flush=True)

        preds, elapsed = _run(path)

        verdict = "FP"; pred_s = "None"
        if gt == ["None"] and not preds:
            verdict = "TP"; pred_s = "None"
        else:
            for p in preds:
                if p in gt:
                    verdict = "TP"; pred_s = p; break
            if verdict == "FP":
                pred_s = "/".join(preds) if preds else "None"

        ox = 'O' if verdict == 'TP' else 'X'
        if verdict == 'TP':
            correct += 1
            tag = "TN(패치→None)" if gt == ["None"] else "TP"
            print(f"✅ {ox} [{tag}] | {elapsed}s")
        else:
            tag = "FP(패치→CWE)" if gt == ["None"] else "FP"
            print(f"❌ {ox} [{tag}] | GT:{gt_s} → Pred:{pred_s} | {elapsed}s")

        total_time += elapsed
        logs.append(f"{fname:<42} | GT:{gt_s:<15} | Pred:{pred_s:<12} | {ox} | {elapsed}s")
        csv_data.append(make_row(LABEL, fname, gt, pred_s, verdict, elapsed))

    m = compute(csv_data)
    rpt = save_report(RESULT_DIR, "bandit", total, correct, total_time, logs, m)
    csv_ = save_csv(RESULT_DIR, "bandit", csv_data)
    acc = correct / total * 100 if total else 0
    print(f"\n완료 | Accuracy:{acc:.1f}% | P:{m['Precision']}% R:{m['Recall']}% F1:{m['F1']}%")
    print(f"  리포트:{rpt}\n  CSV:{csv_}")

if __name__ == "__main__":
    main()