"""
utils/loop.py
LLM 계열 eval_*.py 의 공통 평가 루프.
"""
import os
from typing import Callable
from config import TEST_DIR, RESULT_DIR
from utils.scoring import ground_truth, score
from utils.metrics import compute
from utils.storage import make_row, save_report, save_csv


def run(model_label: str, evaluate_fn: Callable) -> None:
    """
    표준 평가 루프.

    evaluate_fn 시그니처:
      (code: str, is_patch: bool) -> (predicted: str, elapsed: float)
      반환값 추가 있어도 무시 (튜플 앞 2개만 사용)
    """
    print(f"=== [{model_label}] 평가 시작 ===\n")

    files = sorted(f for f in os.listdir(TEST_DIR) if f.endswith('.py'))
    if not files:
        print(f"'{TEST_DIR}' 에 .py 파일이 없습니다."); return

    total = len(files)
    correct = 0; total_time = 0.0
    logs: list[str] = []; csv_data: list[dict] = []

    print(f"총 {total}개 파일 평가\n")

    for idx, fname in enumerate(files, 1):
        path = os.path.join(TEST_DIR, fname)
        gt        = ground_truth(fname)
        gt_str    = "/".join(gt)
        is_patch  = (gt == ["None"])

        print(f"  [{idx:02d}/{total}] {fname}", end=" ... ", flush=True)

        try:
            with open(path, encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"읽기 실패: {e}"); continue

        result = evaluate_fn(code, is_patch=is_patch)
        pred    = result[0]
        elapsed = result[1]

        verdict = score(pred, gt)
        ox      = 'O' if verdict == 'TP' else 'X'

        if verdict == 'TP':
            correct += 1
            tag = "TN(패치→None)" if is_patch else "TP"
            print(f"✅ {ox} [{tag}] | {elapsed}s")
        else:
            tag = "FP(패치→CWE)" if is_patch else "FP"
            print(f"❌ {ox} [{tag}] | GT:{gt_str} → Pred:{pred} | {elapsed}s")

        total_time += elapsed
        logs.append(f"{fname:<42} | GT:{gt_str:<15} | Pred:{pred:<12} | {ox} | {elapsed}s")
        csv_data.append(make_row(model_label, fname, gt, pred, verdict, elapsed))

    m    = compute(csv_data)
    rpt  = save_report(RESULT_DIR, model_label, total, correct, total_time, logs, m)
    csv_ = save_csv(RESULT_DIR, model_label, csv_data)

    acc = correct / total * 100 if total else 0
    print(f"\n완료 | Accuracy:{acc:.1f}% ({correct}/{total})")
    print(f"  TP:{m['TP']} TN:{m['TN']} FP:{m['FP']} FN:{m['FN']}")
    print(f"  P:{m['Precision']}% R:{m['Recall']}% F1:{m['F1']}%")
    print(f"  리포트: {rpt}\n  CSV:    {csv_}")
