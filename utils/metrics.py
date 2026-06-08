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

    return {
        'TP':          tp,
        'TN':          tn,
        'FP':          fp,
        'FN':          fn,
        'FP_patch':    fp_patch,   # 패치→CWE (순수 오탐)
        'FP_misc':     fp_misc,    # 취약→틀린CWE (오분류)
        'FN_miss':     fn_miss,    # 취약→None/UNKNOWN (순수 미탐)
        'Total':       total_files,
        'Correct':     correct,
        'Accuracy':    round(accuracy  * 100, 1),
        'Precision':   round(precision * 100, 1),
        'Recall':      round(recall    * 100, 1),
        'F1':          round(f1        * 100, 1),
        'Avg_Time_s':  round(sum(times) / len(times), 2) if times else 0,
    }