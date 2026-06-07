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


def run(model_label: str, evaluate_fn: Callable,
        script_name: str = "", limit: int = 0, sample: int = 0) -> None:
    """
    표준 평가 루프.

    evaluate_fn 시그니처:
      (code: str, is_patch: bool) -> (predicted: str, elapsed: float)
      반환값 추가 있어도 무시 (튜플 앞 2개만 사용)

    script_name: 저장 파일명에 사용할 스크립트 식별자
      예) "gemini_rag", "llama_rag_ts" 등
      비어있으면 model_label 사용 (기존 동작)
    """
    # 파일명용 레이블: 스크립트명 우선, 없으면 model_label
    file_label = script_name if script_name else model_label
    print(f"=== [{model_label}] 평가 시작 ===\n")

    # 완성된 쌍(test+patch 모두 있는)만 평가 → 클래스 균형 보장
    _all_files = set(os.listdir(TEST_DIR))
    def _has_pair(fname):
        import re as _re
        patch = _re.sub(r'test(\d*)\.py$', r'patch\1.py', fname, flags=_re.IGNORECASE)
        return patch in _all_files
    files = sorted(
        f for f in _all_files
        if f.endswith('.py') and not f.startswith('d.')
        and (_has_pair(f) or 'patch' in f.lower())
    )
    if not files:
        print(f"'{TEST_DIR}' 에 .py 파일이 없습니다."); return

    if sample > 0:
        import random, re as _re
        test_fs  = [f for f in files if _re.search(r'test\d*\.py$', f, _re.I)]
        patch_fs = [f for f in files if _re.search(r'patch\d*\.py$', f, _re.I)]
        k = min(sample, len(test_fs))
        chosen = set(random.sample(test_fs, k))
        stems  = {_re.sub(r'test(\d*)\.py$', r'\1', f, flags=_re.I) for f in chosen}
        files  = sorted(f for f in files if
                        _re.sub(r'(?:test|patch)(\d*)\.py$', r'\1', f, flags=_re.I)
                        in stems)
        print(f"  [sample={sample}] {k}쌍 무작위 → {len(files)}개 파일")
    elif limit > 0:
        files = files[:limit]
        print(f"  [limit={limit}] 앞에서 {limit}개만 평가")
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
            if is_patch:
                tag = "FP(패치→CWE)"
            elif pred in ('None', 'UNKNOWN', 'SKIPPED'):
                tag = "FN(미탐)"   # RAG 미매칭 or 태그 미출력 → 미탐
            else:
                tag = "FP(오분류)" # 취약→틀린CWE
            print(f"❌ {ox} [{tag}] | GT:{gt_str} → Pred:{pred} | {elapsed}s")

        total_time += elapsed
        logs.append(f"{fname:<42} | GT:{gt_str:<15} | Pred:{pred:<12} | {ox} | {elapsed}s")
        csv_data.append(make_row(model_label, fname, gt, pred, verdict, elapsed))

    m    = compute(csv_data)
    rpt  = save_report(RESULT_DIR, file_label, total, correct, total_time, logs, m)
    csv_ = save_csv(RESULT_DIR, file_label, csv_data)

    acc = correct / total * 100 if total else 0
    print(f"\n완료 | Accuracy:{acc:.1f}% ({correct}/{total})")
    print(f"  TP:{m['TP']} TN:{m['TN']} FP:{m['FP']} FN:{m['FN']}")
    print(f"  P:{m['Precision']}% R:{m['Recall']}% F1:{m['F1']}%")
    print(f"  리포트: {rpt}\n  CSV:    {csv_}")