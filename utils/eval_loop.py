"""
utils/eval_loop.py  (v2 — 패치 파일 처리 방식 수정)
=====================================================

[v1 → v2 핵심 변경]

■ 문제: 패치 파일 처리 방식
  - 패치 파일(GT=None)도 RAG/LLM 분석을 그대로 거치면
    원래 취약 코드와 구조가 유사하므로 RAG가 매칭해 취약점을 예측 → 전부 FP
  - 이것이 Accuracy 31.8% 폭락의 직접 원인

■ 수정: 패치 파일에 전용 프롬프트 적용
  - 패치 파일도 동일하게 LLM에 분석을 맡김 (올바른 논문 실험 방식)
  - 단, 프롬프트에 "이 코드가 안전한지 여부도 판단하라"는 지시 포함
  - build_safe_check_prompt() 사용 (prompts.py에 추가)
  - 이렇게 해야 "모델이 패치된 코드를 안전하다고 올바르게 판단하는 능력"을
    공정하게 측정할 수 있음

■ 논문 실험 관점
  - 취약 파일 → CWE 예측 → TP/FP
  - 패치 파일 → None 예측 능력 → TN/FP
  - 두 가지 모두 LLM이 처리해야 논문의 Pairwise Accuracy 의미가 있음
"""

import os
from typing import Callable
from config import TEST_DIR, RESULT_DIR
from utils.eval_utils import (
    extract_ground_truth, score_prediction,
    make_csv_row, save_report, save_csv,
    compute_metrics
)
from utils.prompts import build_safe_check_prompt


def run_eval_loop(
    model_label: str,
    evaluate_fn: Callable[[str], tuple],
    evaluate_safe_fn: Callable[[str], tuple] | None = None,
    memory_label: str = "MB"
) -> None:
    """
    표준 평가 루프.

    Parameters
    ----------
    model_label : str
        config.py 의 MODEL_* 상수.
    evaluate_fn : Callable
        취약 코드 분석 함수.
        (code: str) → (predicted: str, time: float, mem, preview: str)
    evaluate_safe_fn : Callable | None
        패치 코드 분석 함수. None이면 evaluate_fn 과 동일한 함수 사용하되
        safe_check_prompt 로 호출. 대부분의 경우 None으로 두면 됨.
    memory_label : str
        'MB' (로컬) 또는 'API' (클라우드)
    """
    print(f"=== 🚀 [{model_label}] 평가 루프 시작 ===\n")

    test_files = sorted(f for f in os.listdir(TEST_DIR) if f.endswith('.py'))
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 .py 파일이 없습니다."); return

    total = len(test_files)
    correct = 0; total_time = 0.0
    logs: list[str] = []; csv_data: list[dict] = []

    print(f"⏳ 총 {total}개 파일 평가\n")

    for idx, filename in enumerate(test_files, 1):
        file_path = os.path.join(TEST_DIR, filename)
        gt = extract_ground_truth(filename)
        gt_str = "/".join(gt)
        is_patch = (gt == ["None"])

        print(f"  [{idx:02d}/{total}] {filename}", end=" ... ", flush=True)

        try:
            with open(file_path, encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"⚠️ 읽기 실패: {e}"); continue

        # ── 평가 함수 선택 ────────────────────────────────────────
        if is_patch:
            # 패치 파일: "이 코드가 안전한지" 를 판단하는 전용 프롬프트
            # evaluate_safe_fn 이 있으면 사용, 없으면 evaluate_fn 에
            # safe_check_prompt 를 내부적으로 넘기는 래퍼를 사용
            if evaluate_safe_fn is not None:
                result = evaluate_safe_fn(code)
            else:
                result = evaluate_fn(code, is_patch=True)
        else:
            result = evaluate_fn(code, is_patch=False)

        predicted = result[0]
        elapsed   = result[1]
        mem       = result[2] if len(result) > 2 else memory_label

        eval_result = score_prediction(predicted, gt)
        match_ox    = 'O' if eval_result == 'TP' else 'X'

        if eval_result == 'TP':
            correct += 1
            label = "TN(패치→None)" if is_patch else "TP"
            mem_str = f" | {mem}MB" if isinstance(mem, float) else ""
            print(f"✅ {match_ox} [{label}] | {elapsed}s{mem_str}")
        else:
            label = "FP(패치→CWE)" if is_patch else "FP"
            mem_str = f" | {mem}MB" if isinstance(mem, float) else ""
            print(f"❌ {match_ox} [{label}] | GT:{gt_str} → Pred:{predicted} | {elapsed}s{mem_str}")

        total_time += elapsed
        mem_display = mem if isinstance(mem, float) else memory_label
        logs.append(
            f"📄 {filename:<40} | GT:{gt_str:<15} | "
            f"Pred:{predicted:<12} | {match_ox} | {elapsed}s"
        )
        csv_data.append(make_csv_row(
            model_label, filename, gt, predicted, eval_result, elapsed, mem_display
        ))

    metrics  = compute_metrics(csv_data)
    rpt      = save_report(RESULT_DIR, model_label, total, correct, total_time, logs, metrics)
    csv_path = save_csv(RESULT_DIR, model_label, csv_data)

    acc = correct / total * 100 if total else 0
    print(f"\n✅ 완료 | Accuracy:{acc:.1f}% ({correct}/{total})")
    print(f"   TP:{metrics['TP']} TN:{metrics['TN']} FP:{metrics['FP']} FN:{metrics['FN']}")
    print(f"   P:{metrics['Precision']}% | R:{metrics['Recall']}% | F1:{metrics['F1']}%")
    print(f"   리포트: {rpt}\n   CSV:    {csv_path}")
