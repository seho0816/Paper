"""
run_eval_bandit.py
========================
비교군 ①: Bandit (SAST)
변경: compute_metrics() 연동, save_report에 metrics 전달
"""

import os, re, time, json, subprocess
from config import TEST_DIR, RESULT_DIR, MODEL_BANDIT
from utils.eval_utils import (
    extract_ground_truth, score_prediction,
    make_csv_row, save_report, save_csv, compute_metrics
)

TOOL = MODEL_BANDIT


def run_bandit(file_path: str) -> tuple[list[str], float]:
    start = time.time()
    predicted: list[str] = []
    try:
        result = subprocess.run(
            ['bandit', '-r', file_path, '-f', 'json', '-q'],
            capture_output=True, text=True, timeout=60
        )
        output = json.loads(result.stdout)
        for issue in output.get('results', []):
            cwe_info = issue.get('issue_cwe', {})
            if 'id' in cwe_info:
                cwe = f"CWE-{cwe_info['id']}"
                if cwe not in predicted:
                    predicted.append(cwe)
    except subprocess.TimeoutExpired:
        print("⚠️  Bandit 타임아웃")
    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(f"  [Error] {e}")
    return predicted, round(time.time() - start, 2)


def main():
    print(f"=== 🚀 [{TOOL}] 평가 시작 ===\n")
    test_files = sorted(f for f in os.listdir(TEST_DIR) if f.endswith('.py'))
    if not test_files:
        print(f"❌ '{TEST_DIR}' 없음"); return

    total = len(test_files)
    correct = 0; total_time = 0.0
    logs: list[str] = []; csv_data: list[dict] = []

    for idx, filename in enumerate(test_files, 1):
        file_path = os.path.join(TEST_DIR, filename)
        gt = extract_ground_truth(filename)
        print(f"  [{idx:02d}/{total}] {filename}", end=" ... ", flush=True)

        predicted_list, elapsed = run_bandit(file_path)
        pred_str = predicted_list[0] if predicted_list else "None"

        eval_result = "FP"
        if gt == ["None"] and not predicted_list:
            eval_result = "TP"
            pred_str = "None"
        else:
            for p in predicted_list:
                if p in gt:
                    eval_result = "TP"; pred_str = p; break

        match_ox = 'O' if eval_result == 'TP' else 'X'
        gt_str   = "/".join(gt)

        if eval_result == 'TP':
            correct += 1
            print(f"✅ {match_ox} | {elapsed}s")
        else:
            bandit_str = "/".join(predicted_list) if predicted_list else "None"
            print(f"❌ {match_ox} | GT:{gt_str} → Pred:{bandit_str} | {elapsed}s")

        total_time += elapsed
        logs.append(f"📄 {filename:<40} | GT:{gt_str:<15} | Pred:{pred_str:<12} | {match_ox} | {elapsed}s")
        row = make_csv_row(TOOL, filename, gt, pred_str, eval_result, elapsed, "CLI")
        row['Ground_Truth'] = gt_str  # 복수 CWE 유지
        csv_data.append(row)

    metrics = compute_metrics(csv_data)
    rpt = save_report(RESULT_DIR, TOOL, total, correct, total_time, logs, metrics)
    csv = save_csv(RESULT_DIR, TOOL, csv_data)
    acc = correct / total * 100 if total else 0
    print(f"\n✅ 완료 | Accuracy:{acc:.1f}% | P:{metrics['Precision']}% R:{metrics['Recall']}% F1:{metrics['F1']}%")
    print(f"   리포트:{rpt}\n   CSV:{csv}")

if __name__ == "__main__":
    main()
