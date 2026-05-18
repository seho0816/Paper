"""
utils/storage.py
CSV 행 생성, TXT 리포트 저장, CSV 저장.
"""
import os
import csv
import datetime

CSV_FIELDS = ['Model', 'Filename', 'Ground_Truth', 'Prediction', 'Match', 'Time_s']


def make_row(model: str, filename: str,
             gt: list[str], pred: str,
             result: str, elapsed: float) -> dict:
    return {
        'Model':        model,
        'Filename':     os.path.basename(filename),
        'Ground_Truth': "/".join(gt),
        'Prediction':   pred,
        'Match':        'O' if result == 'TP' else 'X',
        'Time_s':       elapsed,
    }


def save_report(result_dir: str, label: str,
                total: int, correct: int,
                total_time: float, logs: list[str],
                m: dict | None = None) -> str:
    os.makedirs(result_dir, exist_ok=True)
    now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(result_dir, f'Eval_{label}_{now}.txt')

    acc     = (correct / total * 100) if total else 0
    avg_t   = round(total_time / total, 2) if total else 0

    with open(path, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write(f"[{label}] CWE 식별 정확도 평가 리포트\n")
        f.write(f"총 {total}개 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Accuracy: {acc:.1f}% | Correct: {correct} | "
                f"Incorrect: {total - correct} | Avg Time: {avg_t}s\n")
        if m:
            f.write(f"Precision: {m['Precision']}% | Recall: {m['Recall']}% | F1: {m['F1']}%\n"
                    f"TP:{m['TP']} TN:{m['TN']} FP:{m['FP']} FN:{m['FN']}\n")
        f.write("\n상세 로그\n" + "-" * 60 + "\n")
        for log in logs:
            f.write(log + "\n")
    return path


def save_csv(result_dir: str, label: str, rows: list[dict]) -> str:
    os.makedirs(result_dir, exist_ok=True)
    now  = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(result_dir, f'Data_{label}_{now}.csv')
    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    return path


def save_summary(result_dir: str, rows: list[dict]) -> str:
    """모든 모델 지표를 한 CSV에 저장 (논문 Table 1)."""
    os.makedirs(result_dir, exist_ok=True)
    now  = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(result_dir, f'Summary_{now}.csv')
    fields = ['Model', 'Accuracy', 'Precision', 'Recall', 'F1',
              'TP', 'TN', 'FP', 'FN', 'Total', 'Avg_Time_s']
    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    return path
