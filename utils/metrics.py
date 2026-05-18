"""
utils/metrics.py
TP/TN/FP/FN 및 Accuracy, Precision, Recall, F1 계산.

[정의]
  TP : 취약 코드 → 올바른 CWE 예측
  TN : 패치 코드 → None 예측 (안전 판정)
  FP : 패치 코드 → CWE 예측 (오탐)
       OR 취약 코드 → 틀린 CWE
  FN : 취약 코드 → None / UNKNOWN / SKIPPED (미탐)
"""


def compute(csv_rows: list[dict]) -> dict:
    """
    CSV 행 목록 → 지표 딕셔너리.
    필요 컬럼: Ground_Truth, Prediction, Match, Time_s
    """
    tp = tn = fp = fn = 0
    times: list[float] = []

    for row in csv_rows:
        gt_str   = row.get('Ground_Truth', '')
        pred     = row.get('Prediction', '')
        match    = row.get('Match', 'X')
        is_patch = (gt_str == 'None')

        if match == 'O':
            if is_patch: tn += 1
            else:        tp += 1
        else:
            if is_patch:
                fp += 1
            else:
                fn += 1 if pred in ('None', 'UNKNOWN', 'SKIPPED') else 0
                fp += 1 if pred not in ('None', 'UNKNOWN', 'SKIPPED') else 0

        try:
            t = float(row.get('Time_s', 0))
            if t > 0:
                times.append(t)
        except (ValueError, TypeError):
            pass

    total     = tp + tn + fp + fn
    accuracy  = (tp + tn) / total   if total         else 0
    precision = tp / (tp + fp)      if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn)      if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)

    return {
        'TP':         tp,
        'TN':         tn,
        'FP':         fp,
        'FN':         fn,
        'Total':      total,
        'Accuracy':   round(accuracy  * 100, 1),
        'Precision':  round(precision * 100, 1),
        'Recall':     round(recall    * 100, 1),
        'F1':         round(f1        * 100, 1),
        'Avg_Time_s': round(sum(times) / len(times), 2) if times else 0,
    }
