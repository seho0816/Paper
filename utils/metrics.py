"""
utils/metrics.py
TP/TN/FP/FN 및 Accuracy, Precision, Recall, F1 계산.

[정의 — 표준 다중분류 기반]
  TP : 취약 코드 → 올바른 CWE 예측
  TN : 패치 코드 → None 예측 (안전 판정)
  FP : 패치 코드 → CWE 예측 (오탐)
       OR 취약 코드 → 틀린 CWE 예측 (오분류)
  FN : 취약 코드 → None / UNKNOWN / SKIPPED (미탐)
       OR 취약 코드 → 틀린 CWE 예측 (오분류 = 해당 CWE를 탐지 못한 것)

[핵심 설계 결정]
  '취약 코드 → 틀린 CWE' 는 FP + FN 양쪽에 집계 (표준 다중분류 방식).
  - FP: 잘못된 CWE를 예측했으므로 오탐
  - FN: 실제 CWE를 맞추지 못했으므로 미탐
  이로써 Recall = TP / (TP + FN) 이 취약 코드 전체 대비 정탐률을 정확히 반영.

  Accuracy = (TP + TN) / (TP + TN + FP_patch + FN)
  단, 오분류는 FP+FN 양쪽이므로 Accuracy는 별도 분모 사용.
  → Accuracy = (TP + TN) / 전체_파일_수 (직관적 정확도)
"""


def compute(csv_rows: list[dict]) -> dict:
    """
    CSV 행 목록 → 지표 딕셔너리.
    필요 컬럼: Ground_Truth, Prediction, Match, Time_s
    """
    tp = tn = fp = fn = 0
    fp_patch = 0    # 패치→CWE 오탐 (FP 전용)
    fp_misc  = 0    # 취약→틀린CWE 오분류 (FP+FN 양쪽)
    fn_miss  = 0    # 취약→None/UNKNOWN/SKIPPED 미탐 (FN 전용)
    total_files = 0
    times: list[float] = []

    for row in csv_rows:
        gt_str   = row.get('Ground_Truth', '')
        pred     = row.get('Prediction', '')
        match    = row.get('Match', 'X')
        is_patch = (gt_str == 'None')
        total_files += 1

        if match == 'O':
            if is_patch:
                tn += 1
            else:
                tp += 1
        else:
            if is_patch:
                # 패치 코드인데 CWE 예측 → FP만
                fp_patch += 1
                fp += 1
            elif pred in ('None', 'UNKNOWN', 'SKIPPED'):
                # 취약 코드인데 탐지 못함 → FN만
                fn_miss += 1
                fn += 1
            else:
                # 취약 코드인데 틀린 CWE → FP + FN 양쪽
                fp_misc += 1
                fp += 1
                fn += 1

        try:
            t = float(row.get('Time_s', 0))
            if t > 0:
                times.append(t)
        except (ValueError, TypeError):
            pass

    # Accuracy: 전체 파일 중 정확히 판정한 비율 (직관적)
    correct   = tp + tn
    accuracy  = correct / total_files      if total_files       else 0
    precision = tp / (tp + fp)             if (tp + fp) > 0     else 0
    recall    = tp / (tp + fn)             if (tp + fn) > 0     else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)

    # Balanced Recall: vulnerable recall + patch recall 평균 (Vul-RAG와 동일 기준)
    vul_total   = tp + fn
    patch_total = tn + fp_patch
    vul_recall   = tp / vul_total   if vul_total   > 0 else None
    patch_recall = tn / patch_total if patch_total > 0 else None
    # 한쪽이 0이면 평균 의미 없음 → 있는 쪽만 사용 OR '-'
    if vul_recall is None and patch_recall is None:
        balanced_recall = None
    elif vul_recall is None:
        balanced_recall = None   # safe_boundary 등 취약파일 없는 유형 → '-'
    elif patch_recall is None:
        balanced_recall = None
    else:
        balanced_recall = (vul_recall + patch_recall) / 2

    # UNKNOWN/SKIPPED 비율 (모델 안정성)
    unk_count = sum(1 for row in csv_rows
                    if row.get('Prediction','') in ('UNKNOWN','SKIPPED'))
    unk_rate  = unk_count / total_files if total_files > 0 else 0

    # Hit@K: RAG 검색 정확도 (취약 코드 test 파일만 대상)
    hit_rows  = [r for r in csv_rows
                 if r.get('Hit_K','-') in ('O','X') and
                    r.get('Ground_Truth','None') != 'None']
    hit_k_total = len(hit_rows)
    hit_k_count = sum(1 for r in hit_rows if r.get('Hit_K') == 'O')
    hit_k_rate  = hit_k_count / hit_k_total if hit_k_total > 0 else None

    # safe_boundary FPR (04 폴더 전용 오탐지율)
    safe_rows  = [r for r in csv_rows if r.get('Test_Type','') == 'safe_boundary']
    safe_total = len(safe_rows)
    safe_fp    = sum(1 for r in safe_rows if r.get('Match','X') == 'X')
    safe_fpr   = safe_fp / safe_total if safe_total > 0 else None  # None=safe 없음

    return {
        'TP':             tp,
        'TN':             tn,
        'FP':             fp,
        'FN':             fn,
        'FP_patch':       fp_patch,
        'FP_misc':        fp_misc,
        'FN_miss':        fn_miss,
        'Total':          total_files,
        'Correct':        correct,
        'Accuracy':       round(accuracy       * 100, 1),
        'Precision':      round(precision      * 100, 1),
        'Recall':         round(recall         * 100, 1),
        'F1':             round(f1             * 100, 1),
        'Balanced_Recall':round(balanced_recall* 100, 1) if balanced_recall is not None else '-',
        'Unknown_Rate':   round(unk_rate        * 100, 1),
        'Unknown_Count':  unk_count,
        # FNR: 취약 파일이 없는 유형(safe_boundary 등)은 정의 불가 → '-'
        'FNR': round((1 - recall) * 100, 1) if (tp + fn) > 0 else '-',
        'Hit_K_Rate':     round(hit_k_rate * 100, 1) if hit_k_rate is not None else '-',
        'Hit_K_Count':    hit_k_count,
        'Hit_K_Total':    hit_k_total,
        'Safe_FPR':       round(safe_fpr * 100, 1) if safe_fpr is not None else '-',
        'Safe_FP':        safe_fp,
        'Safe_Total':     safe_total,
        'Avg_Time_s':     round(sum(times) / len(times), 2) if times else 0,
    }


def compute_by_type(csv_rows: list[dict]) -> dict[str, dict]:
    """
    test_type별로 metrics 집계.
    반환: {test_type: compute() 결과 딕셔너리}
    """
    from collections import defaultdict
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in csv_rows:
        ttype = row.get('Test_Type', 'unknown')
        groups[ttype].append(row)
    return {ttype: compute(rows) for ttype, rows in groups.items()}