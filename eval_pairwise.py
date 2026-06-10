"""eval_pairwise.py — Pairwise Accuracy 평가
모든 eval_*.py 실행 완료 후 실행.
result/ 의 Data_*.csv 를 읽어 vuln/patch 쌍 단위로 재채점.
폴더 유형별(regression/semantic_generalization/...) 분리 집계 포함.
"""
import os, csv, glob, datetime
from collections import defaultdict
from config import RESULT_DIR, TEST_DIR
from utils.pairwise import build_pairs, score_pair
from utils.scoring import ground_truth


def _load_csvs(result_dir: str) -> dict[str, dict[str, str]]:
    """최신 Data_*.csv 로드. {model: {relpath_or_filename: prediction}}"""
    files = sorted(glob.glob(os.path.join(result_dir, "Data_*.csv")))
    if not files:
        raise FileNotFoundError(
            f"'{result_dir}' 에 Data_*.csv 없음. eval_*.py 먼저 실행하세요."
        )
    # 동일 스크립트명 최신 파일만
    latest: dict[str, str] = {}
    for p in files:
        base  = os.path.basename(p)
        parts = base[5:-4].rsplit('_', 2)
        key   = parts[0] if len(parts) == 3 else base
        if key not in latest or p > latest[key]:
            latest[key] = p

    results: dict[str, dict[str, str]] = {}
    for script_name, p in sorted(latest.items()):
        with open(p, encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                model    = row['Model']
                filename = row['Filename']   # relpath or basename
                pred     = row['Prediction']
                results.setdefault(model, {})[filename] = pred
                # basename도 별칭으로 등록 (구버전 CSV 호환)
                results[model].setdefault(os.path.basename(filename), pred)
        print(f"  로드: {os.path.basename(p)}")
    return results


def _compute(model_results: dict, pairs: dict) -> tuple[list, list, dict]:
    """전체 + 유형별 pairwise 집계."""
    detail  = []
    # {model: {test_type: {tp, total}}}
    type_stats: dict[str, dict[str, dict]] = defaultdict(
        lambda: defaultdict(lambda: {"tp": 0, "total": 0})
    )
    overall: dict[str, dict] = defaultdict(lambda: {"tp": 0, "total": 0})

    for model, preds in model_results.items():
        for key, files in pairs.items():
            vuln_rel  = files["vuln"]
            patch_rel = files["patch"]
            test_type = files["test_type"]

            vuln_fname  = os.path.basename(vuln_rel)
            patch_fname = os.path.basename(patch_rel)

            vgt = ground_truth(vuln_fname)
            pgt = ground_truth(patch_fname)

            # relpath 우선, fallback → basename
            vp = preds.get(vuln_rel,  preds.get(vuln_fname,  "MISSING"))
            pp = preds.get(patch_rel, preds.get(patch_fname, "MISSING"))

            res = score_pair(vp, pp, vgt, pgt)
            is_tp = (res == "PAIR_TP")

            overall[model]["total"] += 1
            type_stats[model][test_type]["total"] += 1
            if is_tp:
                overall[model]["tp"] += 1
                type_stats[model][test_type]["tp"] += 1

            detail.append({
                "Model": model, "Pair": key, "Test_Type": test_type,
                "Vuln": vuln_fname, "Patch": patch_fname,
                "GT": "/".join(vgt),
                "Vuln_Pred": vp, "Patch_Pred": pp, "Result": res,
            })

    summary = []
    for model, s in overall.items():
        tp, total = s["tp"], s["total"]
        acc = tp / total * 100 if total else 0
        row = {"Model": model, "Total": total, "TP": tp,
               "FP": total - tp, "Acc_%": f"{acc:.1f}"}
        # 유형별 추가
        for ttype, ts in sorted(type_stats[model].items()):
            t_tp, t_tot = ts["tp"], ts["total"]
            t_acc = t_tp / t_tot * 100 if t_tot else 0
            row[f"Acc_{ttype}_%"] = f"{t_acc:.1f}" if t_tot else "-"
        summary.append(row)

    summary.sort(key=lambda r: float(r["Acc_%"]), reverse=True)
    return detail, summary, dict(type_stats)


def _save(result_dir: str, detail: list, summary: list,
          pairs: dict, type_stats: dict) -> tuple[str, str, str]:
    os.makedirs(result_dir, exist_ok=True)
    now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # 유형 목록 수집
    types = sorted({p["test_type"] for p in pairs.values()})

    # Summary CSV
    sp = os.path.join(result_dir, f"Pairwise_Summary_{now}.csv")
    base_fields = ["Model", "Total", "TP", "FP", "Acc_%"]
    type_fields = [f"Acc_{t}_%" for t in types]
    with open(sp, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=base_fields + type_fields, extrasaction='ignore')
        w.writeheader(); w.writerows(summary)

    # Detail CSV
    dp = os.path.join(result_dir, f"Pairwise_Detail_{now}.csv")
    with open(dp, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=[
            "Model", "Pair", "Test_Type", "Vuln", "Patch",
            "GT", "Vuln_Pred", "Patch_Pred", "Result"
        ])
        w.writeheader(); w.writerows(detail)

    # Report TXT
    rp = os.path.join(result_dir, f"Pairwise_Report_{now}.txt")
    with open(rp, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write(f"Pairwise Accuracy | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
                f" | 쌍:{len(pairs)}개\n")
        f.write("=" * 70 + "\n\n")

        # 전체 요약
        f.write(f"{'Model':<35} {'Pairs':>5} {'TP':>4} {'Acc%':>6}")
        for t in types:
            f.write(f"  {t[:14]:>14}")
        f.write("\n" + "-" * 70 + "\n")
        for r in summary:
            f.write(f"{r['Model']:<35} {r['Total']:>5} {r['TP']:>4} {r['Acc_%']:>5}%")
            for t in types:
                val = r.get(f"Acc_{t}_%", "-")
                f.write(f"  {val:>13}%")
            f.write("\n")

        # 유형별 상세
        f.write("\n\n[ 유형별 쌍 상세 ]\n")
        for t in types:
            f.write(f"\n▶ {t}\n" + "-" * 50 + "\n")
            type_pairs = {k: v for k, v in pairs.items() if v["test_type"] == t}
            f.write(f"  쌍 수: {len(type_pairs)}\n")

        # 모델별 쌍 결과
        f.write("\n\n[ 모델별 쌍 결과 ]\n" + "-" * 70 + "\n")
        cur_model = None
        for r in sorted(detail, key=lambda x: (x["Model"], x["Test_Type"], x["Pair"])):
            if r["Model"] != cur_model:
                cur_model = r["Model"]
                f.write(f"\n▶ {cur_model}\n")
            icon = "✅" if r["Result"] == "PAIR_TP" else "❌"
            f.write(f"  {icon} [{r['Test_Type']}] {r['Pair']}"
                    f" | GT:{r['GT']} | 취약:{r['Vuln_Pred']} | 패치:{r['Patch_Pred']}\n")
    return sp, dp, rp


def main():
    print("=== Pairwise Accuracy 평가 시작 ===\n")
    pairs = build_pairs(TEST_DIR)
    if not pairs:
        print("vuln/patch 쌍 없음"); return

    # 유형별 쌍 수 출력
    from collections import Counter
    type_cnt = Counter(v["test_type"] for v in pairs.values())
    print(f"구성된 쌍: {len(pairs)}개")
    for t, n in sorted(type_cnt.items()):
        print(f"  {t}: {n}쌍")

    print(f"\nCSV 로드 중...")
    try:
        model_results = _load_csvs(RESULT_DIR)
    except FileNotFoundError as e:
        print(f"❌ {e}"); return
    print(f"  로드된 모델: {list(model_results.keys())}\n")

    detail, summary, type_stats = _compute(model_results, pairs)

    # 콘솔 출력
    types = sorted({p["test_type"] for p in pairs.values()})
    print(f"{'Model':<35} {'Pairs':>5} {'TP':>4} {'Acc%':>6}")
    print("-" * 58)
    for r in summary:
        print(f"{r['Model']:<35} {r['Total']:>5} {r['TP']:>4} {r['Acc_%']:>5}%")
    if types:
        print(f"\n유형별 Pairwise Accuracy:")
        for t in types:
            print(f"  {t}:")
            for r in summary[:5]:  # 상위 5개 모델만
                val = r.get(f"Acc_{t}_%", "-")
                print(f"    {r['Model']:<33} {val}%")

    s, d, rep = _save(RESULT_DIR, detail, summary, pairs, type_stats)
    print(f"\n✅ 저장 완료\n  Summary:{s}\n  Detail:{d}\n  Report:{rep}")


if __name__ == "__main__":
    main()