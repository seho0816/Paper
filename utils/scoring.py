"""
utils/scoring.py
파일명 → Ground Truth, 모델 응답 → 예측 CWE, 채점(TP/FP).
"""
import re
import os


def _cwes_from_name(filename: str) -> list[str]:
    """
    파일명에서 CWE 번호를 추출하는 내부 헬퍼.

    지원 패턴:
      CWE-XXX          : 명시적
      CWE-XXX_YYY      : 언더스코어 직후 숫자 (CWE-117_532)
      CWE-XXX,YYY      : 쉼표 직후 숫자   (CWE-117,532)
      CWE-XXX_CWE-YYY  : 두 번째 CWE 명시
    """
    base = os.path.basename(filename)
    explicit  = re.findall(r'CWE-(\d{3,4})', base, re.IGNORECASE)
    after_sep = re.findall(r'CWE-\d{3,4}[_,](\d{3,4})', base, re.IGNORECASE)
    seen: list[str] = []
    for n in explicit + after_sep:
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


def predicted_cwe(result_text: str) -> str:
    """
    모델 응답 → 예측 CWE.
    마지막 <CWE>...</CWE> 태그 기준.
    None → "None", 숫자 → "CWE-XXX", 태그 없음 → "UNKNOWN"
    """
    matches = re.findall(r'<CWE>\s*(.*?)\s*</CWE>',
                         result_text, re.IGNORECASE | re.DOTALL)
    if not matches:
        return "UNKNOWN"
    raw = matches[-1].strip()
    if raw.lower() == 'none':
        return "None"
    m = re.search(r'(\d{3,4})', raw)
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
