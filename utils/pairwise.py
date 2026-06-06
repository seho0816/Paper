"""
utils/pairwise.py
취약/패치 쌍 구성 및 Pairwise Accuracy 채점.

[파일명 규칙]
  취약 코드: CWE-XXX_test.py / CWE-XXX_01_test.py / CWE-XXX_02_test.py
  패치 코드: CWE-XXX_patch.py / CWE-XXX_01_patch.py

  키 생성 예시:
    CWE-862_test.py      → "CWE-862"
    CWE-862_01_test.py   → "CWE-862_01"
    CWE-862_01_patch.py  → "CWE-862_01"
    CWE-117,532_Test.py  → "CWE-117_CWE-532"
    CWE-338_CWE-343_test.py → "CWE-338_CWE-343"
"""
import os
import re
from utils.scoring import ground_truth, score


def _pair_key(fname: str) -> str:
    """
    파일명에서 쌍 키를 추출.
    _test / _patch / .py 를 제거한 stem을 키로 사용.
    쉼표 구분 다중 CWE(CWE-117,532)는 CWE-117_CWE-532 형태로 정규화.
    """
    base = os.path.basename(fname)
    stem = base[:-3] if base.endswith('.py') else base
    stem = re.sub(r'[_](?:test|patch)$', '', stem, flags=re.IGNORECASE)

    # 쉼표 구분 다중 CWE 정규화: "CWE-117,532" → "CWE-117_CWE-532"
    def _normalize(s):
        def repl(m):
            first = m.group(1)
            rest  = m.group(2).split(',')
            parts = [f"CWE-{first}"] + [f"CWE-{n.strip()}" for n in rest if n.strip()]
            return "_".join(sorted(set(parts)))
        return re.sub(r'CWE-(\d{3,4})((?:,\d{3,4})+)', repl, s, flags=re.IGNORECASE)

    return _normalize(stem)


def build_pairs(test_dir: str) -> dict[str, dict]:
    """
    test_dir 내 파일을 순회하여 vuln/patch 쌍을 구성한다.

    반환: { "CWE-862_01": {"vuln": "CWE-862_01_test.py", "patch": "CWE-862_01_patch.py"}, ... }
    """
    vuln_map:  dict[str, str] = {}
    patch_map: dict[str, str] = {}

    for fname in os.listdir(test_dir):
        if not fname.endswith('.py'):
            continue
        k = _pair_key(fname)
        if not k:
            continue
        if '_patch' in fname.lower():
            patch_map[k] = fname
        else:
            vuln_map[k] = fname

    return {
        k: {"vuln": vuln_map[k], "patch": patch_map[k]}
        for k in vuln_map if k in patch_map
    }


def score_pair(vuln_pred: str, patch_pred: str,
               vuln_gt: list[str], patch_gt: list[str]) -> str:
    """
    취약 CWE 정확히 예측 AND 패치 None 판정 → PAIR_TP
    그 외 → PAIR_FP
    """
    ok_vuln  = score(vuln_pred,  vuln_gt)  == "TP"
    ok_patch = score(patch_pred, patch_gt) == "TP"
    return "PAIR_TP" if (ok_vuln and ok_patch) else "PAIR_FP"