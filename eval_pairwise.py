"""eval_pairwise.py — Pairwise Accuracy 평가
모든 eval_*.py 실행 완료 후 실행.
result_int/ 의 Data_*.csv 를 읽어 vuln/patch 쌍 단위로 재채점.
"""
import os, csv, glob, datetime
from config import RESULT_DIR, TEST_DIR
from utils.pairwise import build_pairs, score_pair
from utils.scoring import ground_truth


def _load_csvs(result_dir):
    files = sorted(glob.glob(os.path.join(result_dir, "Data_*.csv")))
    if not files:
        raise FileNotFoundError(f"'{result_dir}' 에 Data_*.csv 없음. eval_*.py 먼저 실행하세요.")
    results = {}
    for p in files:
        with open(p, encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                results.setdefault(row['Model'], {})[row['Filename']] = row['Prediction']
    return results


def _compute(model_results, pairs):
    detail = []; summary = []
    for model, preds in model_results.items():
        tp = fp = 0
        for key, files in pairs.items():
            vf, pf = files["vuln"], files["patch"]
            vgt = ground_truth(vf); pgt = ground_truth(pf)
            vp  = preds.get(vf, "MISSING")
            pp  = preds.get(pf, "MISSING")
            res = score_pair(vp, pp, vgt, pgt)
            if res == "PAIR_TP": tp += 1
            else:                fp += 1
            detail.append({'Model':model,'Pair':key,'Vuln':vf,'Patch':pf,
                            'GT':"/".join(vgt),'Vuln_Pred':vp,'Patch_Pred':pp,'Result':res})
        total = tp + fp
        acc = tp / total * 100 if total else 0
        summary.append({'Model':model,'Total':total,'TP':tp,'FP':fp,'Acc_%':f"{acc:.1f}"})
    summary.sort(key=lambda r: float(r['Acc_%']), reverse=True)
    return detail, summary


def _save(result_dir, detail, summary, pairs):
    os.makedirs(result_dir, exist_ok=True)
    now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    sp = os.path.join(result_dir, f"Pairwise_Summary_{now}.csv")
    with open(sp, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['Model','Total','TP','FP','Acc_%'])
        w.writeheader(); w.writerows(summary)

    dp = os.path.join(result_dir, f"Pairwise_Detail_{now}.csv")
    with open(dp, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['Model','Pair','Vuln','Patch','GT','Vuln_Pred','Patch_Pred','Result'])
        w.writeheader(); w.writerows(detail)

    rp = os.path.join(result_dir, f"Pairwise_Report_{now}.txt")
    with open(rp, 'w', encoding='utf-8') as f:
        f.write("=" * 65 + "\n")
        f.write(f"Pairwise Accuracy 리포트 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} | 쌍:{len(pairs)}개\n")
        f.write("=" * 65 + "\n\n")
        f.write(f"{'Model':<35} {'Pairs':>5} {'TP':>4} {'FP':>4} {'Acc%':>6}\n")
        f.write("-" * 58 + "\n")
        for r in summary:
            f.write(f"{r['Model']:<35} {r['Total']:>5} {r['TP']:>4} {r['FP']:>4} {r['Acc_%']:>5}%\n")
        f.write("\n\n[ 쌍별 상세 ]\n" + "-" * 65 + "\n")
        cur = None
        for r in sorted(detail, key=lambda x: (x['Model'], x['Pair'])):
            if r['Model'] != cur:
                cur = r['Model']; f.write(f"\n▶ {cur}\n")
            icon = "✅" if r['Result'] == "PAIR_TP" else "❌"
            f.write(f"  {icon} [{r['Pair']}] GT:{r['GT']} | 취약:{r['Vuln_Pred']} | 패치:{r['Patch_Pred']}\n")
    return sp, dp, rp


def main():
    print("=== Pairwise Accuracy 평가 시작 ===\n")
    pairs = build_pairs(TEST_DIR)
    if not pairs:
        print("vuln/patch 쌍 없음"); return

    print(f"구성된 쌍: {len(pairs)}개")
    for k, v in sorted(pairs.items()):
        print(f"  {k}: {v['vuln']}  ↔  {v['patch']}")

    print(f"\nCSV 로드 중...")
    try:
        model_results = _load_csvs(RESULT_DIR)
    except FileNotFoundError as e:
        print(f"❌ {e}"); return
    print(f"  로드된 모델: {list(model_results.keys())}\n")

    detail, summary = _compute(model_results, pairs)

    print(f"{'Model':<35} {'Pairs':>5} {'TP':>4} {'FP':>4} {'Acc%':>6}")
    print("-" * 58)
    for r in summary:
        print(f"{r['Model']:<35} {r['Total']:>5} {r['TP']:>4} {r['FP']:>4} {r['Acc_%']:>5}%")

    s, d, r = _save(RESULT_DIR, detail, summary, pairs)
    print(f"\n✅ 저장 완료\n  Summary:{s}\n  Detail:{d}\n  Report:{r}")

if __name__ == "__main__":
    main()
