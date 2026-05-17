"""
utils/eval_utils.py  (v3 — 파일명 쉼표 버그픽스)
=================================================

[v2 → v3 변경사항]

■ 버그픽스 3: CWE-XXX,YYY 파일명 패턴 처리 누락
  - 실제 데이터셋 파일명: CWE-117,532_test.py / CWE-942,798_test.py
  - 기존: 쉼표(,) 뒤 숫자를 CWE로 인식 못해 GT 누락
  - 수정: r'CWE-\d{3,4},(\d{3,4})' 패턴 추가
  - 결과: CWE-117,532_test.py → ['CWE-117','CWE-532'] 정상 추출

■ TP/TN/FP/FN 정의 명확화 (논문 Table 정확성)
  - TP  : 취약 코드 → 올바른 CWE 예측
  - TN  : 패치 코드 → None 예측 (안전 판정)
  - FP  : 패치 코드에서 없는 취약점 탐지 (오탐)
         OR 취약 코드에서 틀린 CWE 예측
  - FN  : 취약 코드 → None/UNKNOWN/SKIPPED (미탐)
"""

import re
import os
import csv
import datetime
import psutil

CSV_FIELDNAMES = [
    'Model', 'Filename', 'Ground_Truth', 'Prediction',
    'Match', 'Time_s', 'Memory_MB'
]


# ════════════════════════════════════════════════════════════════
# 내부 헬퍼: 파일명에서 CWE 번호 목록 추출
# ════════════════════════════════════════════════════════════════

def _extract_cwes_from_filename(filename: str) -> list[str]:
    """
    파일명에서 CWE 번호 목록을 추출한다.

    지원 패턴 (실제 데이터셋 파일명 기준):
      패턴 1: CWE-XXX          → CWE-117, CWE-798 등
      패턴 2: CWE-XXX_YYY      → CWE-117_532 에서 532 추출 (언더스코어 구분)
      패턴 3: CWE-XXX,YYY      → CWE-117,532 에서 532 추출 (쉼표 구분) ← v3 추가
      패턴 4: CWE-XXX_CWE-YYY  → CWE-338_CWE-343 (명시적 두 번째 CWE)

    예시:
      'CWE-117_532_Test.py'    → ['CWE-117', 'CWE-532']  (패턴 2)
      'CWE-117,532_test.py'    → ['CWE-117', 'CWE-532']  (패턴 3) ← 신규
      'CWE-942,798_test.py'    → ['CWE-942', 'CWE-798']  (패턴 3) ← 신규
      'CWE-338_CWE-343test.py' → ['CWE-338', 'CWE-343']  (패턴 1+4)
      'CWE-285_test.py'        → ['CWE-285']              (패턴 1)
    """
    base = os.path.basename(filename)

    # 패턴 1+4: CWE- 접두어 있는 명시적 번호
    explicit = re.findall(r'CWE-(\d{3,4})', base, re.IGNORECASE)

    # 패턴 2: CWE-XXX_YYY (언더스코어 직후 숫자)
    implicit_underscore = re.findall(r'CWE-\d{3,4}_(\d{3,4})', base, re.IGNORECASE)

    # 패턴 3: CWE-XXX,YYY (쉼표 직후 숫자) ← v3 신규
    implicit_comma = re.findall(r'CWE-\d{3,4},(\d{3,4})', base, re.IGNORECASE)

    seen: list[str] = []
    for n in explicit + implicit_underscore + implicit_comma:
        cwe = f"CWE-{n}"
        if cwe not in seen:
            seen.append(cwe)
    return seen


# ════════════════════════════════════════════════════════════════
# 1. Ground Truth 추출
# ════════════════════════════════════════════════════════════════

def extract_ground_truth(filename: str) -> list[str]:
    """
    파일명에서 Ground Truth CWE 목록을 추출한다.

    '_patch' 포함 → ["None"]  (안전한 코드 = 취약점 없음)
    CWE 패턴 추출 → ["CWE-XXX", ...]
    패턴 없음    → ["None"]

    실제 데이터셋 파일명 검증 결과 (v3):
      CWE-117,532_test.py   → ['CWE-117', 'CWE-532']  ✅
      CWE-942,798_test.py   → ['CWE-942', 'CWE-798']  ✅
      CWE-117,532_patch.py  → ['None']                 ✅
      CWE-338_CWE-343test.py → ['CWE-338', 'CWE-343'] ✅
      CWE-285_test.py        → ['CWE-285']             ✅
      CWE-770test.py         → ['CWE-770']             ✅
    """
    base = os.path.basename(filename)
    if '_patch' in base.lower():
        return ["None"]
    cwes = _extract_cwes_from_filename(base)
    return cwes if cwes else ["None"]


# ════════════════════════════════════════════════════════════════
# 2. 예측 CWE 추출
# ════════════════════════════════════════════════════════════════

def extract_predicted_cwe(result_text: str) -> str:
    """
    모델 응답에서 <CWE>...</CWE> 태그(마지막 것)를 추출하여 반환.
    None → 'None', CWE-798 또는 798 → 'CWE-798', 태그 없음 → 'UNKNOWN'
    """
    matches = re.findall(
        r'<CWE>\s*(.*?)\s*</CWE>',
        result_text,
        re.IGNORECASE | re.DOTALL
    )
    if not matches:
        return "UNKNOWN"
    raw = matches[-1].strip()
    if raw.lower() == 'none':
        return "None"
    number = re.search(r'(\d{3,4})', raw)
    return f"CWE-{number.group(1)}" if number else "UNKNOWN"


# ════════════════════════════════════════════════════════════════
# 3. 채점
# ════════════════════════════════════════════════════════════════

def score_prediction(predicted: str, ground_truths: list[str]) -> str:
    """
    단일 파일 채점.

    TP 조건:
      - 패치 파일(GT=['None']) + predicted='None' → TN 역할이지만 TP로 통일 반환
      - 취약 파일(GT=['CWE-XXX',...]) + predicted가 GT 중 하나와 일치
    FP 조건: 그 외 전부
    """
    if ground_truths == ["None"] and predicted == "None":
        return "TP"   # 패치 파일을 안전하다고 올바르게 판단
    if predicted in ground_truths:
        return "TP"
    return "FP"


# ════════════════════════════════════════════════════════════════
# 4. 지표 계산 (논문 Table용)
# ════════════════════════════════════════════════════════════════

def compute_metrics(csv_rows: list[dict]) -> dict:
    """
    CSV 행 목록으로부터 TP/TN/FP/FN 및 파생 지표를 계산한다.

    [정의]
      TP : 취약 코드 → 올바른 CWE 예측
      TN : 패치 코드 → 'None' 예측  (안전 판정)
      FP : 패치 코드 → CWE 예측 (없는 취약점 탐지, 오탐)
           OR 취약 코드 → 틀린 CWE 예측
      FN : 취약 코드 → None/UNKNOWN/SKIPPED (취약점 미탐)

    [지표]
      Accuracy  = (TP + TN) / Total
      Precision = TP / (TP + FP)
      Recall    = TP / (TP + FN)
      F1        = 2*P*R / (P+R)
    """
    tp = tn = fp = fn = 0
    times: list[float] = []
    mems:  list[float] = []

    for row in csv_rows:
        gt_str  = row.get('Ground_Truth', '')
        pred    = row.get('Prediction', '')
        match   = row.get('Match', 'X')         # 'O' or 'X'
        is_patch = (gt_str == 'None')

        if match == 'O':
            if is_patch:
                tn += 1   # TN: 패치를 None으로 올바르게 판정
            else:
                tp += 1   # TP: 취약점 CWE 정확히 탐지
        else:
            if is_patch:
                fp += 1   # FP: 패치 코드에서 취약점 오탐
            else:
                if pred in ('None', 'UNKNOWN', 'SKIPPED'):
                    fn += 1   # FN: 취약점 미탐
                else:
                    fp += 1   # FP: 틀린 CWE 예측

        try:
            t = float(row.get('Time_s', 0))
            if t > 0:
                times.append(t)
        except (ValueError, TypeError):
            pass

        try:
            m = row.get('Memory_MB', '')
            if m not in ('API', 'CLI', '', None):
                mems.append(float(m))
        except (ValueError, TypeError):
            pass

    total     = tp + tn + fp + fn
    accuracy  = (tp + tn) / total   if total          else 0
    precision = tp / (tp + fp)      if (tp + fp) > 0  else 0
    recall    = tp / (tp + fn)      if (tp + fn) > 0  else 0
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
        'Avg_Mem_MB': round(sum(mems)  / len(mems),  2) if mems  else 'N/A',
    }


# ════════════════════════════════════════════════════════════════
# 5. Pairwise 채점
# ════════════════════════════════════════════════════════════════

def build_pairwise_map(test_dir: str) -> dict[str, dict]:
    """
    test_dir 내 파일을 순회하여 vuln/patch 쌍을 구성한다.
    _extract_cwes_from_filename() 사용으로 쉼표/언더스코어 패턴 모두 지원.

    반환: { 'CWE-117_CWE-532': {'vuln': '...', 'patch': '...'}, ... }
    """
    all_files = [f for f in os.listdir(test_dir) if f.endswith('.py')]

    vuln_map:  dict[str, str] = {}
    patch_map: dict[str, str] = {}

    for fname in all_files:
        cwes = _extract_cwes_from_filename(fname)
        if not cwes:
            continue
        key = "_".join(sorted(set(cwes)))

        if '_patch' in fname.lower():
            patch_map[key] = fname
        else:
            vuln_map[key] = fname

    return {
        key: {"vuln": vuln_map[key], "patch": patch_map[key]}
        for key in vuln_map
        if key in patch_map
    }


def score_pairwise(vuln_pred: str, patch_pred: str,
                   vuln_gt: list[str], patch_gt: list[str]) -> str:
    """
    취약 코드 CWE 정확히 예측 AND 패치 코드 None 판정 → PAIR_TP, 그 외 PAIR_FP
    """
    vuln_ok  = score_prediction(vuln_pred,  vuln_gt)  == "TP"
    patch_ok = score_prediction(patch_pred, patch_gt) == "TP"
    return "PAIR_TP" if (vuln_ok and patch_ok) else "PAIR_FP"


# ════════════════════════════════════════════════════════════════
# 6. 저장 헬퍼
# ════════════════════════════════════════════════════════════════

def get_memory_mb() -> float:
    """현재 Python 프로세스 RSS 메모리(MB). 로컬 모델 전용; API 모델엔 사용 안 함."""
    return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)


def make_csv_row(model: str, filename: str,
                 ground_truths: list[str], predicted: str,
                 eval_result: str, inference_time: float,
                 memory_mb) -> dict:
    return {
        'Model':        model,
        'Filename':     os.path.basename(filename),
        'Ground_Truth': "/".join(ground_truths),
        'Prediction':   predicted,
        'Match':        'O' if eval_result == 'TP' else 'X',
        'Time_s':       inference_time,
        'Memory_MB':    memory_mb,
    }


def save_report(result_dir: str, model_label: str,
                total_files: int, correct: int,
                total_time: float, logs: list[str],
                metrics: dict | None = None) -> str:
    os.makedirs(result_dir, exist_ok=True)
    now_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(result_dir, f'Eval_{model_label}_{now_str}.txt')

    accuracy = (correct / total_files * 100) if total_files > 0 else 0
    avg_time = round(total_time / total_files, 2) if total_files > 0 else 0

    with open(path, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write(f"📊 [{model_label}] CWE 식별 정확도 평가 리포트\n")
        f.write(f"📁 총 평가 파일: {total_files}개 | "
                f"🕒 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"| Accuracy: {accuracy:.1f}% | Correct: {correct} | "
                f"Incorrect: {total_files - correct} | Avg Time: {avg_time}s |\n")
        if metrics:
            f.write(f"| Precision: {metrics['Precision']}% | "
                    f"Recall: {metrics['Recall']}% | F1: {metrics['F1']}% |\n"
                    f"| TP:{metrics['TP']} TN:{metrics['TN']} "
                    f"FP:{metrics['FP']} FN:{metrics['FN']} |\n")
        f.write("\n📝 상세 로그\n" + "-" * 60 + "\n")
        for log in logs:
            f.write(log + "\n")
    return path


def save_csv(result_dir: str, model_label: str, csv_data: list[dict]) -> str:
    os.makedirs(result_dir, exist_ok=True)
    now_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(result_dir, f'Data_{model_label}_{now_str}.csv')
    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(csv_data)
    return path


def save_summary_table(result_dir: str, rows: list[dict]) -> str:
    """모든 모델 지표를 하나의 CSV로 저장 (논문 Table 1)."""
    os.makedirs(result_dir, exist_ok=True)
    now_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(result_dir, f'Summary_AllModels_{now_str}.csv')
    fields = ['Model', 'Accuracy', 'Precision', 'Recall', 'F1',
              'TP', 'TN', 'FP', 'FN', 'Total', 'Avg_Time_s', 'Avg_Mem_MB']
    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    return path
