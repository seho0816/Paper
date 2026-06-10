"""eval_bandit.py — 비교군 ①: Bandit (SAST)"""

# ── 실행 옵션 ──────────────────────────────────────────────
# python eval_bandit.py                    전체 평가
# python eval_bandit.py --limit 10         앞에서 10개만
# python eval_bandit.py --sample 5         무작위 5쌍
# python eval_bandit.py --resume           중단 후 이어하기
# python eval_bandit.py --folder 00        00_legacy_db_derived만
# python eval_bandit.py --folder 01        01_regression만
# python eval_bandit.py --folder 02        02_semantic_generalization만
# python eval_bandit.py --folder 03        03_structural_generalization만
# python eval_bandit.py --folder 04        04_safe_boundary만
# python eval_bandit.py --folder 05        05_external_independent만
# python eval_bandit.py --folder 01 --sample 10   조합 가능
# ────────────────────────────────────────────────────────────

import os, re, time, json, subprocess
import glob as _bg
from config import TEST_DIR, RESULT_DIR, MODEL_BANDIT
from utils.scoring import ground_truth, score
from utils.metrics import compute, compute_by_type
from utils.storage import make_row, save_report, save_csv

LABEL = MODEL_BANDIT

def _extract_test_type(filepath: str) -> str:
    folder = os.path.basename(os.path.dirname(filepath))
    return re.sub(r"^\d+_", "", folder) or "unknown"

def _run(path):
    start = time.time()
    found = []
    try:
        r = subprocess.run(['bandit', '-r', path, '-f', 'json', '-q'],
                           capture_output=True, text=True, timeout=60)
        for issue in json.loads(r.stdout).get('results', []):
            cwe = issue.get('issue_cwe', {})
            if 'id' in cwe:
                c = f"CWE-{cwe['id']}"
                if c not in found: found.append(c)
    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(f"  Bandit 오류: {e}")
    return found, round(time.time() - start, 2)

def main():
    print(f"=== [{LABEL}] 평가 시작 ===\n")

    # ── 파일 목록: 전체 경로 기준 수집 ──────────────────────────
    all_paths = sorted(
        p for p in _bg.glob(os.path.join(TEST_DIR, "**", "*.py"), recursive=True)
        if not os.path.basename(p).startswith("d.")
    )

    # 완전한 쌍(test+patch 모두 존재)만 포함. orphan 제외.
    # 완전한 쌍(test+patch 모두 존재)만 포함 — 모든 폴더 동일 기준
    complete_pairs: set = set()
    for p in all_paths:
        fname  = os.path.basename(p)
        folder = os.path.dirname(p)
        if re.search(r"test\d*\.py$", fname, re.I):
            patch_name = re.sub(r"test(\d*)\.py$", r"patch\1.py", fname, re.I)
            patch_path = os.path.join(folder, patch_name)
            if os.path.exists(patch_path):
                complete_pairs.add(p)
                complete_pairs.add(patch_path)

    files = [p for p in all_paths if p in complete_pairs]
    if _args.folder:
        ff = _args.folder.lower()
        files = [p for p in files
                 if ff in os.path.basename(os.path.dirname(p)).lower() or os.path.basename(os.path.dirname(p)).lower().startswith(ff)]
        print(f"  [folder={_args.folder}] {len(files)}개 파일 필터")

    import argparse as _ap
    _p = _ap.ArgumentParser()
    _p.add_argument('--limit',  type=int, default=0)
    _p.add_argument('--sample', type=int, default=0)
    _p.add_argument('--resume', action='store_true',
                    help='중단된 평가 이어하기')
    _p.add_argument('--folder', type=str, default='',
                    help='특정 폴더만 평가 (예: 01, 02_semantic, safe_boundary)')
    _args = _p.parse_args()

    import random as _rnd
    if _args.sample > 0:
        test_fs = [f for f in files if re.search(r"test\d*\.py$", os.path.basename(f), re.I)]
        chosen  = set(_rnd.sample(test_fs, min(_args.sample, len(test_fs))))
        stems   = {re.sub(r"(?:test|patch)(\d*)\.py$", r"\1", os.path.basename(f), re.I) for f in chosen}
        files   = sorted(f for f in files if
                         re.sub(r"(?:test|patch)(\d*)\.py$", r"\1", os.path.basename(f), re.I) in stems)
        print(f"  [sample={_args.sample}] {len(chosen)}쌍 → {len(files)}개 파일")
    elif _args.limit > 0:
        files = files[:_args.limit]

    if not files:
        print("파일 없음"); return

    # resume: 체크포인트 로드
    import json as _js
    from utils.loop import _ckpt_path, _load_ckpt, _save_ckpt
    done_map = _load_ckpt("bandit") if _args.resume else {}
    if done_map:
        print(f"  [resume] 완료 {len(done_map)}개 제외\n")

    total = len(files); correct = 0; total_time = 0.0
    logs = []; csv_data = []
    # 완료된 결과 복원
    for r in done_map.values():
        csv_data.append(r['row']); logs.append(r['log'])
        if r['verdict'] == 'TP': correct += 1
        total_time += r['elapsed']
    print(f"총 {total}개 파일 평가\n")

    remaining = [f for f in files if f not in done_map]
    for idx, fpath in enumerate(remaining, start=len(done_map)+1):
        fname     = os.path.basename(fpath)
        test_type = _extract_test_type(fpath)

        # GT 결정:
        #   04_safe_boundary → 무조건 None (완전한 안전 코드)
        #   나머지 폴더      → 파일명에서 추출
        # is_patch=False 유지 — 모델/Bandit에게 힌트 없음
        if "04_safe_boundary" in fpath.replace("\\", "/"):
            gt       = ["None"]
            is_patch = False
        else:
            gt       = ground_truth(fname)
            is_patch = (gt == ["None"])
        gt_s = "/".join(gt)
        print(f"  [{idx:03d}/{total}] {fname}", end=" ... ", flush=True)

        preds, elapsed = _run(fpath)

        # B안 채점: score() 함수와 동일 기준
        if is_patch:
            pred_s  = "/".join(preds) if preds else "None"
            verdict = score(pred_s, gt)   # preds 없으면 TN, 있으면 FP
        else:
            # test 파일: GT CWE 중 하나라도 탐지하면 TP
            matched = [p for p in preds if p in gt]
            if matched:
                pred_s  = matched[0]
                verdict = "TP"
            else:
                pred_s  = "/".join(preds) if preds else "None"
                verdict = score(pred_s, gt)

        ox = "O" if verdict == "TP" else "X"
        if verdict == "TP":
            correct += 1
            tag = "TN(패치→None)" if is_patch else "TP"
            print(f"✅ {ox} [{tag}] | {test_type} | {elapsed}s")
        else:
            tag = "FP(패치→CWE)" if is_patch else "FP/FN"
            print(f"❌ {ox} [{tag}] | {test_type} | GT:{gt_s} → Pred:{pred_s} | {elapsed}s")

        total_time += elapsed
        logs.append(f"{fname:<42} | {test_type:<30} | GT:{gt_s:<15} | Pred:{pred_s:<12} | {ox} | {elapsed}s")
        row = make_row(LABEL, fname, gt, pred_s, verdict, elapsed, test_type)
        csv_data.append(row)
        if _args.resume:
            done_map[fpath] = {'row': row, 'log': logs[-1], 'verdict': verdict, 'elapsed': elapsed}
            _save_ckpt('bandit', done_map)

    m      = compute(csv_data)
    m_type = compute_by_type(csv_data)
    rpt    = save_report(RESULT_DIR, "bandit", total, correct, total_time, logs, m, m_type)
    csv_   = save_csv(RESULT_DIR, "bandit", csv_data)

    acc = correct / total * 100 if total else 0
    print(f"\n완료 | Accuracy:{acc:.1f}% ({correct}/{total})")
    print(f"  TP:{m['TP']} TN:{m['TN']} FP:{m['FP']} FN:{m['FN']}")
    print(f"  P:{m['Precision']}% R:{m['Recall']}% F1:{m['F1']}")
    if m_type:
        print("  유형별 성능:")
        for ttype, tm in sorted(m_type.items()):
            print(f"    {ttype:<35} P:{tm['Precision']}% R:{tm['Recall']}% F1:{tm['F1']}")
    ckpt = _ckpt_path('bandit')
    if os.path.exists(ckpt) and len(csv_data) == total:
        os.remove(ckpt)
    print(f"  리포트:{rpt}\n  CSV:{csv_}")

if __name__ == "__main__":
    main()