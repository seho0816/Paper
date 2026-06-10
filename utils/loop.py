"""
utils/loop.py
LLM 계열 eval_*.py 의 공통 평가 루프.

폴더 구조 (py_dataset 하위):
  00_legacy_db_derived/
  01_regression/
  02_semantic_generalization/
  03_structural_generalization/
  04_safe_boundary/
  05_external_independent/

[평가 원칙]
  eval은 폴더명을 모른다. GT는 오직 파일명(ground_truth(fname))으로만 결정.
  04_safe_boundary 파일도 다른 폴더와 동일하게 처리.
  → 04 파일의 이름에 CWE가 없으면 GT=None (자연스럽게 safe 처리)
  → 폴더 기반 GT 강제는 치팅이므로 금지

test_type은 폴더명에서 자동 추출 (채점 분류용, 평가 자체에 영향 없음).
"""
import os
import json
import glob as _glob
import re as _re
import threading
import concurrent.futures
from typing import Callable
from config import TEST_DIR, RESULT_DIR
from utils.scoring import ground_truth, score
from utils.metrics import compute, compute_by_type
from utils.storage import make_row, save_report, save_csv

MAX_EVAL_WORKERS = 20   # 동시 평가 스레드 수


def _extract_test_type(filepath: str) -> str:
    folder = os.path.basename(os.path.dirname(filepath))
    return _re.sub(r"^\d+_", "", folder) or "unknown"


def _ckpt_path(file_label: str) -> str:
    os.makedirs(RESULT_DIR, exist_ok=True)
    return os.path.join(RESULT_DIR, f"eval_ckpt_{file_label}.json")


def _load_ckpt(file_label: str) -> dict:
    path = _ckpt_path(file_label)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return {r["fpath"]: r for r in data.get("done", [])}
    except Exception:
        return {}


def _save_ckpt(file_label: str, done_map: dict) -> None:
    try:
        with open(_ckpt_path(file_label), "w", encoding="utf-8") as f:
            json.dump({"done": list(done_map.values())}, f, ensure_ascii=False)
    except Exception:
        pass


def _evaluate_one(fpath: str, evaluate_fn: Callable, model_label: str) -> dict:
    """단일 파일 평가. 폴더명 무관, 파일명으로만 GT 결정."""
    fname     = os.path.basename(fpath)
    test_type = _extract_test_type(fpath)

    # GT 결정:
    #   04_safe_boundary → 무조건 None (설계 결정: 완전한 안전 코드)
    #   나머지 폴더      → 파일명에서 추출
    # is_patch는 항상 False (모델은 탐지 프롬프트 사용, 폴더 정보 없음)
    if "04_safe_boundary" in fpath.replace("\\", "/"):
        gt       = ["None"]
        is_patch = False   # 모델에게 힌트 없음 — 탐지 프롬프트 사용
    else:
        gt       = ground_truth(fname)
        is_patch = (gt == ["None"])  # patch 파일만 True
    gt_str = "/".join(gt)

    try:
        with open(fpath, encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        return dict(fpath=fpath, fname=fname, gt=gt, gt_str=gt_str,
                    is_patch=is_patch, test_type=test_type,
                    pred="UNKNOWN", elapsed=0.0, error=f"읽기 실패: {e}")

    pred, elapsed = "UNKNOWN", 0.0
    for _attempt in range(3):
        try:
            result        = evaluate_fn(code, is_patch=is_patch)
            pred, elapsed = result[0], result[1]
            # Hit@K: evaluate_fn이 3번째 값으로 retrieved_cwes 반환 시 캡처
            retrieved_cwes = result[2] if len(result) > 2 else None
            break
        except Exception as e:
            msg     = str(e).lower()
            is_rate = ("rate" in msg or "429" in msg or "quota" in msg
                       or "overloaded" in msg or "resource" in msg)
            if is_rate and _attempt < 2:
                import time as _t
                _t.sleep(2 ** (_attempt + 2))
                continue
            pred, elapsed = "UNKNOWN", 0.0
            break

    return dict(fpath=fpath, fname=fname, gt=gt, gt_str=gt_str,
                is_patch=is_patch, test_type=test_type,
                pred=pred, elapsed=elapsed, error=None,
                retrieved_cwes=retrieved_cwes)


def run(model_label: str, evaluate_fn: Callable,
        script_name: str = "", limit: int = 0, sample: int = 0,
        resume: bool = False, folder_filter: str = "") -> None:
    """
    표준 평가 루프 (멀티스레딩 + resume + folder_filter).
    폴더 구조를 평가 자체에 반영하지 않음 — 블라인드 평가.
    """
    file_label = script_name if script_name else model_label
    print(f"=== [{model_label}] 평가 시작 (스레드={MAX_EVAL_WORKERS}) ===\n")

    # ── 파일 목록: 완전한 쌍(test+patch)만 포함 ───────────────
    all_paths = sorted(
        _glob.glob(os.path.join(TEST_DIR, "**", "*.py"), recursive=True)
    )
    all_paths = [p for p in all_paths if not os.path.basename(p).startswith("d.")]

    # folder_filter 적용 (평가 범위 제한, GT 판단과 무관)
    if folder_filter:
        ff = folder_filter.lower()
        def _folder_match(fpath: str) -> bool:
            folder = os.path.basename(os.path.dirname(fpath)).lower()
            return folder == ff or folder.startswith(ff) or ff in folder
        all_paths = [p for p in all_paths if _folder_match(p)]
        print(f"  [folder={folder_filter}] {len(all_paths)}개 파일 필터")

    # 완전한 쌍 구성 — 모든 폴더 동일 기준
    complete_pairs: set = set()
    for p in all_paths:
        fname  = os.path.basename(p)
        folder = os.path.dirname(p)
        if _re.search(r"test\d*\.py$", fname, _re.I):
            patch_name = _re.sub(r"test(\d*)\.py$", r"patch\1.py", fname, flags=_re.I)
            patch_path = os.path.join(folder, patch_name)
            if os.path.exists(patch_path):
                complete_pairs.add(p)
                complete_pairs.add(patch_path)

    files = [p for p in all_paths if p in complete_pairs]

    if not files:
        print(f"평가할 파일 없음 (완전한 쌍 기준)"); return

    if sample > 0:
        import random
        test_fs = [f for f in files if _re.search(r"test\d*\.py$", os.path.basename(f), _re.I)]
        k       = min(sample, len(test_fs))
        chosen  = set(random.sample(test_fs, k))
        stems   = {_re.sub(r"test(\d*)\.py$", r"\1", os.path.basename(f), flags=_re.I)
                   for f in chosen}
        files   = sorted(f for f in files if
                         _re.sub(r"(?:test|patch)(\d*)\.py$", r"\1",
                                 os.path.basename(f), flags=_re.I) in stems)
        print(f"  [sample={sample}] {k}쌍 → {len(files)}개 파일")
    elif limit > 0:
        files = files[:limit]
        print(f"  [limit={limit}] {limit}개 파일")

    # ── resume ──────────────────────────────────────────────────
    done_map: dict = {}
    if resume:
        done_map = _load_ckpt(file_label)
        if done_map:
            print(f"  [resume] 완료 {len(done_map)}개 제외, "
                  f"남은 {len(files)-len(done_map)}개 평가\n")

    csv_data:  list[dict] = []
    logs:      list[str]  = []
    correct    = 0
    total_time = 0.0
    lock       = threading.Lock()

    for r in done_map.values():
        csv_data.append(r["row"]); logs.append(r["log"])
        if r["verdict"] == "TP": correct += 1
        total_time += r["elapsed"]

    remaining = [f for f in files if f not in done_map]
    total     = len(files)

    if remaining:
        print(f"총 {total}개 파일 평가\n")

    # ── 멀티스레딩 평가 ─────────────────────────────────────────
    future_to_path: dict = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_EVAL_WORKERS) as executor:
            future_to_path = {
                executor.submit(_evaluate_one, fpath, evaluate_fn, model_label): fpath
                for fpath in remaining
            }
            for i, future in enumerate(
                concurrent.futures.as_completed(future_to_path),
                start=len(done_map) + 1
            ):
                try:
                    res = future.result()
                except Exception as e:
                    fpath = future_to_path[future]
                    res = dict(fpath=fpath, fname=os.path.basename(fpath),
                               gt=["UNKNOWN"], gt_str="UNKNOWN", is_patch=False,
                               test_type="unknown", pred="UNKNOWN", elapsed=0.0, error=str(e))

                with lock:
                    fname     = res["fname"]
                    fpath     = res["fpath"]
                    gt        = res["gt"]
                    gt_str    = res["gt_str"]
                    is_patch  = res["is_patch"]
                    test_type = res["test_type"]
                    pred      = res["pred"]
                    elapsed   = res["elapsed"]

                    verdict = score(pred, gt)
                    ox      = "O" if verdict == "TP" else "X"
                    # Hit@K: 검색된 CWE 중 GT 포함 여부
                    retrieved = res.get("retrieved_cwes")
                    hit_k = None
                    if retrieved and not is_patch:
                        gt_cwe = gt[0] if gt else ""
                        hit_k = gt_cwe in retrieved

                    if verdict == "TP":
                        correct += 1
                        tag = "TN(패치->None)" if is_patch else "TP"
                        print(f"  [{i:03d}/{total}] {fname} ... [OK] {ox} [{tag}] | {test_type} | {elapsed:.1f}s", flush=True)
                    else:
                        if is_patch:  tag = "FP(패치->CWE)"
                        elif pred in ("None","UNKNOWN","SKIPPED"): tag = "FN(미탐)"
                        else:         tag = "FP(오분류)"
                        print(f"  [{i:03d}/{total}] {fname} ... [--] {ox} [{tag}] | {test_type} | GT:{gt_str} -> Pred:{pred} | {elapsed:.1f}s", flush=True)

                    total_time += elapsed
                    row = make_row(model_label, fname, gt, pred, verdict, elapsed, test_type,
                                  hit_k=hit_k)
                    log = f"{fname:<42} | {test_type:<30} | GT:{gt_str:<15} | Pred:{pred:<12} | {ox} | {elapsed:.1f}s"
                    csv_data.append(row); logs.append(log)

                    if resume:
                        done_map[fpath] = {"fpath": fpath, "row": row, "log": log,
                                           "verdict": verdict, "elapsed": elapsed}
                        _save_ckpt(file_label, done_map)

    except KeyboardInterrupt:
        print("\n\n⚠️ [중단됨] 지금까지 결과를 저장합니다...")
        _save_ckpt(file_label, done_map)
        print(f"  재실행: python {file_label.split('_')[0]}*.py --resume\n")
        try:
            for future in future_to_path: future.cancel()
        except Exception:
            pass

    # ── 결과 저장 ────────────────────────────────────────────────
    processed = len(csv_data)
    if processed == 0:
        print("저장할 평가 결과가 없습니다."); return

    ckpt = _ckpt_path(file_label)
    if os.path.exists(ckpt) and processed >= total:
        os.remove(ckpt)

    m      = compute(csv_data)
    m_type = compute_by_type(csv_data)
    rpt    = save_report(RESULT_DIR, file_label, processed, correct, total_time, logs, m, m_type)
    csv_   = save_csv(RESULT_DIR, file_label, csv_data)

    acc = correct / processed * 100 if processed else 0
    print(f"\n완료 | Accuracy:{acc:.1f}% ({correct}/{processed})")
    print(f"  TP:{m['TP']} TN:{m['TN']} FP:{m['FP']} FN:{m['FN']}")
    print(f"  P:{m['Precision']}% R:{m['Recall']}% F1:{m['F1']}")
    if m_type:
        print("  유형별 성능:")
        for ttype, tm in sorted(m_type.items()):
            print(f"    {ttype:<35} P:{tm['Precision']}% R:{tm['Recall']}% F1:{tm['F1']}")
    print(f"  리포트: {rpt}\n  CSV:    {csv_}")