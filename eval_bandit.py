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

import argparse as _ap
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
    # ── 1. 인자 파싱 ────────────────────────────────────────
    _p = _ap.ArgumentParser()
    _p.add_argument('--limit',  type=int, default=0)
    _p.add_argument('--sample', type=int, default=0)
    _p.add_argument('--resume', action='store_true', help='중단된 평가 이어하기')
    _p.add_argument('--folder', type=str, default='',
                    help='특정 폴더만 평가 (예: 01, 02, 04)')
    _args = _p.parse_args()

    print(f"=== [{LABEL}] 평가 시작 ===\n")

    # ── 2. 파일 목록: 완전한 쌍만 ────────────────────────────
    all_paths = sorted(
        p for p in _bg.glob(os.path.join(TEST_DIR, "**", "*.py"), recursive=True)
        if not os.path.basename(p).startswith("d.")
    )

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

    # ── 3. 폴더 필터 ────────────────────────────────────────
    if _args.folder:
        ff = _args.folder.lower()
        files = [p for p in files
                 if ff in os.path.basename(os.path.dirname(p)).lower()
                 or os.path.basename(os.path.dirname(p)).lower().startswith(ff)]
        print(f"  [folder={_args.folder}] {len(files)}개 파일 필터")

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

    # ── 4. Resume 체크포인트 ─────────────────────────────────
    from utils.loop import _ckpt_path, _load_ckpt, _save_ckpt
    done_map = _load_ckpt("bandit") if _args.resume else {}
    if done_map:
        print(f"  [resume] 완료 {len(done_map)}개 제외\n")

    total = len(files); correct = 0; total_time = 0.0
    logs = []; csv_data = []
    for r in done_map.values():
        csv_data.append(r['row']); logs.append(r['log'])
        if r['verdict'] == 'TP': correct += 1
        total_time += r['elapsed']
    print(f"총 {total}개 파일 평가\n")

    # ── 5. 평가 루프 ─────────────────────────────────────────
    remaining = [f for f in files if f not in done_map]
    for idx, fpath in enumerate(remaining, start=len(done_map)+1):
        fname     = os.path.basename(fpath)
        test_type = _extract_test_type(fpath)

        # GT 결정: 04_safe_boundary → 무조건 None (블라인드 평가)
        if "04_safe_boundary" in fpath.replace("\\", "/"):
            gt       = ["None"]
            is_patch = False
        else:
            gt       = ground_truth(fname)
            is_patch = (gt == ["None"])
        gt_s = "/".join(gt)
        print(f"  [{idx:03d}/{total}] {fname}", end=" ... ", flush=True)

        preds, elapsed = _run(fpath)

        # 채점
        if is_patch:
            pred_s  = "/".join(preds) if preds else "None"
            verdict = score(pred_s, gt)
        else:
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

    # ── 6. 결과 저장 ─────────────────────────────────────────
    m      = compute(csv_data)
    m_type = compute_by_type(csv_data)
    rpt    = save_report(RESULT_DIR, "bandit", total, correct, total_time, logs, m, m_type)
    csv_   = save_csv(RESULT_DIR, "bandit", csv_data)

    acc = correct / total * 100 if total else 0
    print(f"\n완료 | Accuracy:{acc:.1f}% ({correct}/{total})")
    print(f"  TP:{m['TP']} TN:{m['TN']} FP:{m['FP']} FN:{m['FN']}")
    print(f"  P:{m['Precision']}% R:{m['Recall']}% F1:{m['F1']}% | Balanced_Recall:{m.get('Balanced_Recall','-')}%")
    print(f"  FNR:{m.get('FNR','-')}% | UNKNOWN:{m.get('Unknown_Rate','-')}% | safe_FPR:{m.get('Safe_FPR','-')}%")
    if m_type:
        print("  유형별 성능:")
        print(f"    {'유형':<35} {'N':>5} {'P%':>6} {'R%':>6} {'F1%':>6} {'FNR%':>6} {'FPR%':>6} {'Bal.R%':>7}")
        for ttype, tm in sorted(m_type.items()):
            fnr = tm.get('FNR', '-')
            br  = tm.get('Balanced_Recall', '-')
            fpr = tm.get('Safe_FPR', '-') if ttype == 'safe_boundary' else '-'
            n   = tm.get('Total', 0)
            print(f"    {ttype:<35} {n:>5} {tm['Precision']:>6}% {tm['Recall']:>6}% {tm['F1']:>6}% {fnr:>6}% {fpr:>6} {br:>7}%")
    ckpt = _ckpt_path('bandit')
    if os.path.exists(ckpt) and len(csv_data) == total:
        os.remove(ckpt)
    print(f"  리포트:{rpt}\n  CSV:{csv_}")

if __name__ == "__main__":
    main()