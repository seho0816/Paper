"""
run_pairwise_eval.py  (v3)
==========================
Pairwise Accuracy 평가.
모든 run_eval_*.py 실행 완료 후 마지막에 한 번만 실행.

출력 파일 (visualize_results.py 가 읽는 파일):
  result_int/Pairwise_Summary_<ts>.csv   ← 모델별 요약
  result_int/Pairwise_Detail_<ts>.csv    ← 쌍별 상세
  result_int/Pairwise_Report_<ts>.txt    ← 텍스트 리포트
"""

import os, csv, glob, datetime
from config import RESULT_DIR, TEST_DIR
from utils.eval_utils import (
    build_pairwise_map, score_pairwise, extract_ground_truth
)


def load_all_csvs(result_dir: str) -> dict[str, dict[str, str]]:
    """Data_*.csv 전부 로드 → {model: {filename: prediction}}"""
    pattern   = os.path.join(result_dir, "Data_*.csv")
    csv_files = sorted(glob.glob(pattern))
    if not csv_files:
        raise FileNotFoundError(
            f"'{result_dir}' 에 Data_*.csv 없음. run_eval_*.py 먼저 실행하세요."
        )
    model_results: dict[str, dict[str, str]] = {}
    for path in csv_files:
        with open(path, encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                model = row['Model']
                model_results.setdefault(model, {})[row['Filename']] = row['Prediction']
    return model_results


def compute_pairwise(
    model_results: dict[str, dict[str, str]],
    pairs: dict[str, dict]
) -> tuple[list[dict], list[dict]]:

    detail_rows: list[dict] = []
    summary_rows: list[dict] = []

    for model, file_pred in model_results.items():
        pair_tp = 0; pair_fp = 0

        for pair_key, pair_files in pairs.items():
            vuln_fname  = pair_files["vuln"]
            patch_fname = pair_files["patch"]
            vuln_gt     = extract_ground_truth(vuln_fname)
            patch_gt    = extract_ground_truth(patch_fname)   # → ["None"]

            vuln_pred  = file_pred.get(vuln_fname,  "MISSING")
            patch_pred = file_pred.get(patch_fname, "MISSING")

            result     = score_pairwise(vuln_pred, patch_pred, vuln_gt, patch_gt)
            if result == "PAIR_TP": pair_tp += 1
            else:                   pair_fp += 1

            detail_rows.append({
                'Model':       model,
                'Pair_Key':    pair_key,
                'Vuln_File':   vuln_fname,
                'Patch_File':  patch_fname,
                'GT_CWE':      "/".join(vuln_gt),
                'Vuln_Pred':   vuln_pred,
                'Patch_Pred':  patch_pred,
                'Pair_Result': result,
            })

        total_pairs  = pair_tp + pair_fp
        pairwise_acc = pair_tp / total_pairs * 100 if total_pairs else 0
        summary_rows.append({
            'Model':          model,
            'Total_Pairs':    total_pairs,
            'Pair_TP':        pair_tp,
            'Pair_FP':        pair_fp,
            'Pairwise_Acc_%': f"{pairwise_acc:.1f}",
        })

    summary_rows.sort(key=lambda r: float(r['Pairwise_Acc_%']), reverse=True)
    return detail_rows, summary_rows


def save_all(result_dir: str, detail_rows: list[dict],
             summary_rows: list[dict], pairs: dict) -> tuple[str, str, str]:
    """Summary CSV / Detail CSV / TXT Report 저장. visualize_results.py 가 읽음."""
    os.makedirs(result_dir, exist_ok=True)
    now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # ── Pairwise_Summary_*.csv (visualize_results.py 필수 입력) ──
    s_path = os.path.join(result_dir, f"Pairwise_Summary_{now}.csv")
    with open(s_path, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=[
            'Model', 'Total_Pairs', 'Pair_TP', 'Pair_FP', 'Pairwise_Acc_%'])
        w.writeheader(); w.writerows(summary_rows)

    # ── Pairwise_Detail_*.csv ────────────────────────────────────
    d_path = os.path.join(result_dir, f"Pairwise_Detail_{now}.csv")
    with open(d_path, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=[
            'Model', 'Pair_Key', 'Vuln_File', 'Patch_File',
            'GT_CWE', 'Vuln_Pred', 'Patch_Pred', 'Pair_Result'])
        w.writeheader(); w.writerows(detail_rows)

    # ── Pairwise_Report_*.txt ────────────────────────────────────
    r_path = os.path.join(result_dir, f"Pairwise_Report_{now}.txt")
    with open(r_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("📊 Pairwise Accuracy 평가 리포트\n")
        f.write(f"🕒 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} | "
                f"평가 쌍: {len(pairs)}개\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"{'Model':<35} {'Pairs':>6} {'TP':>5} {'FP':>5} {'Acc%':>7}\n")
        f.write("-" * 60 + "\n")
        for row in summary_rows:
            f.write(f"{row['Model']:<35} {row['Total_Pairs']:>6} "
                    f"{row['Pair_TP']:>5} {row['Pair_FP']:>5} "
                    f"{row['Pairwise_Acc_%']:>6}%\n")

        f.write("\n\n[ 쌍별 상세 결과 ]\n" + "-" * 70 + "\n")
        cur = None
        for row in sorted(detail_rows, key=lambda r: (r['Model'], r['Pair_Key'])):
            if row['Model'] != cur:
                cur = row['Model']
                f.write(f"\n▶ {cur}\n")
            icon = "✅" if row['Pair_Result'] == "PAIR_TP" else "❌"
            f.write(f"  {icon} [{row['Pair_Key']}] "
                    f"GT:{row['GT_CWE']} | "
                    f"취약예측:{row['Vuln_Pred']} | "
                    f"패치예측:{row['Patch_Pred']}\n")

    return s_path, d_path, r_path


def main():
    print("=== 🔬 Pairwise Accuracy 평가 시작 ===\n")

    # 1. 쌍 구성
    pairs = build_pairwise_map(TEST_DIR)
    if not pairs:
        print("❌ vuln/patch 쌍 없음. 파일명 확인 필요."); return

    print(f"🔗 구성된 쌍: {len(pairs)}개")
    for k, v in sorted(pairs.items()):
        print(f"   {k}: {v['vuln']}  ↔  {v['patch']}")

    # 2. CSV 로드
    print(f"\n📂 '{RESULT_DIR}' CSV 로드 중...")
    try:
        model_results = load_all_csvs(RESULT_DIR)
    except FileNotFoundError as e:
        print(f"❌ {e}"); return

    models_found = list(model_results.keys())
    print(f"   로드된 모델 ({len(models_found)}개): {models_found}\n")

    # 3. Pairwise 채점
    detail_rows, summary_rows = compute_pairwise(model_results, pairs)

    # 4. 터미널 출력
    print("=" * 60)
    print("📊 Pairwise Accuracy 결과")
    print("=" * 60)
    print(f"{'Model':<35} {'Pairs':>6} {'TP':>5} {'FP':>5} {'Acc%':>7}")
    print("-" * 60)
    for row in summary_rows:
        print(f"{row['Model']:<35} {row['Total_Pairs']:>6} "
              f"{row['Pair_TP']:>5} {row['Pair_FP']:>5} "
              f"{row['Pairwise_Acc_%']:>6}%")

    # 5. 저장 (반드시 실행 — visualize_results.py 가 이 파일을 읽음)
    s, d, r = save_all(RESULT_DIR, detail_rows, summary_rows, pairs)
    print(f"\n✅ 저장 완료")
    print(f"   Summary : {s}  ← visualize_results.py 가 읽는 파일")
    print(f"   Detail  : {d}")
    print(f"   Report  : {r}")


if __name__ == "__main__":
    main()
