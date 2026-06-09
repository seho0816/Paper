"""
utils/loop.py
LLM 계열 eval_*.py 의 공통 평가 루프.

폴더 구조 (py_dataset 하위):
  00_legacy_db_derived/     <- 기존 파일들 (test+patch 쌍)
  01_regression/
  02_semantic_generalization/
  03_structural_generalization/
  04_safe_boundary/         <- 안전 코드 단독 파일 (GT=None, 쌍 불필요)
  05_external_independent/

test_type 은 파일이 속한 폴더명(번호 접두사 제거)에서 자동 추출.
"""
import os
import glob as _glob
import re as _re
from typing import Callable
from config import TEST_DIR, RESULT_DIR
from utils.scoring import ground_truth, score
from utils.metrics import compute, compute_by_type
from utils.storage import make_row, save_report, save_csv

_SAFE_FOLDER = "04_safe_boundary"


def _extract_test_type(filepath: str) -> str:
    folder = os.path.basename(os.path.dirname(filepath))
    return _re.sub(r"^\d+_", "", folder) or "unknown"


def _is_safe_folder(filepath: str) -> bool:
    return _SAFE_FOLDER in filepath.replace("\\", "/")


def run(model_label: str, evaluate_fn: Callable,
        script_name: str = "", limit: int = 0, sample: int = 0) -> None:
    """표준 평가 루프. py_dataset 하위폴더 재귀 탐색."""
    file_label = script_name if script_name else model_label
    print(f"=== [{model_label}] 평가 시작 ===\n")

    all_paths = sorted(
        _glob.glob(os.path.join(TEST_DIR, "**", "*.py"), recursive=True)
    )
    all_paths = [p for p in all_paths if not os.path.basename(p).startswith("d.")]

    def _has_pair(fpath: str) -> bool:
        fname = os.path.basename(fpath)
        folder = os.path.dirname(fpath)
        patch_name = _re.sub(r"test(\d*)\.py$", r"patch\1.py", fname, flags=_re.IGNORECASE)
        return os.path.exists(os.path.join(folder, patch_name))

    files = []
    for p in all_paths:
        fname = os.path.basename(p)
        if _is_safe_folder(p):
            files.append(p)
        else:
            if _has_pair(p) or "patch" in fname.lower():
                files.append(p)

    if not files:
        print(f"'{TEST_DIR}' 하위에 평가할 .py 파일이 없습니다."); return

    if sample > 0:
        import random
        test_fs = [f for f in files if _re.search(r"test\d*\.py$", os.path.basename(f), _re.I)]
        k = min(sample, len(test_fs))
        chosen = set(random.sample(test_fs, k))
        stems  = {_re.sub(r"test(\d*)\.py$", r"\1", os.path.basename(f), flags=_re.I)
                  for f in chosen}
        files  = sorted(f for f in files if
                        _re.sub(r"(?:test|patch)(\d*)\.py$", r"\1",
                                os.path.basename(f), flags=_re.I) in stems)
        print(f"  [sample={sample}] {k}쌍 무작위 -> {len(files)}개 파일")
    elif limit > 0:
        files = files[:limit]
        print(f"  [limit={limit}] 앞에서 {limit}개만 평가")

    total = len(files)
    correct = 0; total_time = 0.0
    logs: list[str] = []; csv_data: list[dict] = []
    print(f"총 {total}개 파일 평가\n")

    for idx, fpath in enumerate(files, 1):
        fname     = os.path.basename(fpath)
        test_type = _extract_test_type(fpath)

        if _is_safe_folder(fpath):
            gt = ["None"]
        else:
            gt = ground_truth(fname)

        gt_str   = "/".join(gt)
        is_patch = (gt == ["None"])
        print(f"  [{idx:02d}/{total}] {fname}", end=" ... ", flush=True)

        try:
            with open(fpath, encoding="utf-8") as f:
                code = f.read()
        except Exception as e:
            print(f"읽기 실패: {e}"); continue

        pred, elapsed = "UNKNOWN", 0.0
        for _attempt in range(3):
            try:
                result = evaluate_fn(code, is_patch=is_patch)
                pred, elapsed = result[0], result[1]
                break
            except Exception as e:
                msg = str(e).lower()
                is_rate = ("rate" in msg or "429" in msg or "quota" in msg
                           or "overloaded" in msg or "resource" in msg)
                if is_rate and _attempt < 2:
                    import time as _t
                    wait = 2 ** (_attempt + 2)
                    print(f"\n    rate limit, {wait}s 대기 후 재시도...", flush=True)
                    _t.sleep(wait)
                    continue
                print(f"\n    평가 오류 [{fname}]: {e}", flush=True)
                pred, elapsed = "UNKNOWN", 0.0
                break

        verdict = score(pred, gt)
        ox      = "O" if verdict == "TP" else "X"

        if verdict == "TP":
            correct += 1
            tag = "TN(패치->None)" if is_patch else "TP"
            print(f"[OK] {ox} [{tag}] | {test_type} | {elapsed}s")
        else:
            if is_patch:
                tag = "FP(패치->CWE)"
            elif pred in ("None", "UNKNOWN", "SKIPPED"):
                tag = "FN(미탐)"
            else:
                tag = "FP(오분류)"
            print(f"[--] {ox} [{tag}] | {test_type} | GT:{gt_str} -> Pred:{pred} | {elapsed}s")

        total_time += elapsed
        logs.append(
            f"{fname:<42} | {test_type:<30} | GT:{gt_str:<15} | Pred:{pred:<12} | {ox} | {elapsed}s"
        )
        csv_data.append(make_row(model_label, fname, gt, pred, verdict, elapsed, test_type))

    m      = compute(csv_data)
    m_type = compute_by_type(csv_data)
    rpt    = save_report(RESULT_DIR, file_label, total, correct, total_time, logs, m, m_type)
    csv_   = save_csv(RESULT_DIR, file_label, csv_data)

    acc = correct / total * 100 if total else 0
    print(f"\n완료 | Accuracy:{acc:.1f}% ({correct}/{total})")
    print(f"  TP:{m['TP']} TN:{m['TN']} FP:{m['FP']} FN:{m['FN']}")
    print(f"  P:{m['Precision']}% R:{m['Recall']}% F1:{m['F1']}")
    if m_type:
        print("  유형별 성능:")
        for ttype, tm in sorted(m_type.items()):
            print(f"    {ttype:<35} P:{tm['Precision']}% R:{tm['Recall']}% F1:{tm['F1']}")
    print(f"  리포트: {rpt}\n  CSV:    {csv_}")