"""
utils/scoring.py
파일명 → Ground Truth, 모델 응답 → 예측 CWE, 채점(TP/FP).
"""
import re
import os


def _cwes_from_name(fname: str) -> list[str]:
    """
    파일명에서 primary CWE 목록 추출.
    규칙:
      CWE-117,532_test.py  → [CWE-117, CWE-532]  (쉼표: 다중 CWE)
      CWE-338_CWE-343_test.py → [CWE-338, CWE-343]  (CWE- 접두사: 다중 CWE)
      CWE-22_01_test.py   → [CWE-22]            (_01은 variant index, CWE 아님)
      CWE-22_02_test.py   → [CWE-22]
      CWE-259_04_test.py  → [CWE-259]
    """
    import re as _re
    base = _re.sub(r'\.py$', '', fname, flags=_re.IGNORECASE)

    # 쉼표 구분 다중 CWE 먼저 추출: CWE-117,532 → [117, 532]
    comma_cwes = []
    for m in _re.finditer(r'CWE-(\d{1,4})((?:,\d{1,4})+)', base, _re.IGNORECASE):
        comma_cwes.append(m.group(1))
        for extra in m.group(2).split(','):
            if extra: comma_cwes.append(extra)

    # CWE- 접두사가 있는 모든 번호 추출
    prefixed_cwes = [m.group(1) for m in _re.finditer(r'CWE-(\d{1,4})', base, _re.IGNORECASE)]

    # variant index 필터: 앞에 CWE-숫자가 있고 뒤에 _또는end인 1~2자리 숫자는 제외
    # 예: CWE-22_01 → '01'은 CWE-22 다음의 variant
    filtered = []
    for i, num in enumerate(prefixed_cwes):
        # 이 숫자 앞에 다른 CWE가 있고 1~2자리면 variant index로 간주
        if len(num) <= 2 and i > 0:
            continue  # variant index 제외
        filtered.append(num)

    # 쉼표 CWE와 합산
    all_nums = filtered[:]
    for n in comma_cwes:
        if n not in all_nums:
            all_nums.append(n)

    seen = []
    for n in all_nums:
        cwe = f"CWE-{n}"
        if cwe not in seen:
            seen.append(cwe)
    return seen


def ground_truth(filename: str) -> list[str]:
    """
    파일명 → Ground Truth CWE 목록.
      _patch 포함  → ["None"]
      CWE 패턴 없음 → ["None"]
    """
    base = os.path.basename(filename)
    if '_patch' in base.lower():
        return ["None"]
    cwes = _cwes_from_name(base)
    return cwes if cwes else ["None"]


def predicted_cwe(result_text) -> str:
    """
    모델 응답 → 예측 CWE.
    마지막 <CWE>...</CWE> 태그 기준.
    None → "None", 숫자 → "CWE-XXX", 태그 없음 → "UNKNOWN"
    """
    if result_text is None:
        return "UNKNOWN"
    raw = str(result_text)
    matches = re.findall(r'<CWE>\s*(.*?)\s*</CWE>',
                         result_text, re.IGNORECASE | re.DOTALL)
    if not matches:
        return "UNKNOWN"
    raw = matches[-1].strip()
    if raw.lower() == 'none':
        return "None"
    m = re.search(r'(\d{1,4})', raw.strip())
    return f"CWE-{m.group(1)}" if m else "UNKNOWN"


def score(pred: str, gt: list[str]) -> str:
    """
    TP: 패치→None 정확 판정, 또는 취약→GT 중 하나 일치.
    FP: 그 외.
    """
    if gt == ["None"] and pred == "None":
        return "TP"
    if pred in gt:
        return "TP"
    return "FP"