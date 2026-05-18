"""
utils/pairwise.py
취약/패치 쌍 구성 및 Pairwise Accuracy 채점.
"""
import os
import re
from utils.scoring import ground_truth, score


def build_pairs(test_dir: str) -> dict[str, dict]:
    """
    test_dir 내 파일을 순회하여 vuln/patch 쌍을 구성한다.

    네이밍 규칙:
      취약 코드: CWE-XXX_test.py  / CWE-XXX_vuln.py
      패치 코드: CWE-XXX_patch.py

    반환: { "CWE-XXX": {"vuln": "파일명", "patch": "파일명"}, ... }
    """
    def _key(fname: str) -> str:
        base = os.path.basename(fname)
        explicit  = re.findall(r'CWE-(\d{3,4})', base, re.IGNORECASE)
        after_sep = re.findall(r'CWE-\d{3,4}[_,](\d{3,4})', base, re.IGNORECASE)
        cwes = []
        for n in explicit + after_sep:
            c = f"CWE-{n}"
            if c not in cwes:
                cwes.append(c)
        return "_".join(sorted(set(cwes))) if cwes else ""

    vuln_map:  dict[str, str] = {}
    patch_map: dict[str, str] = {}

    for fname in os.listdir(test_dir):
        if not fname.endswith('.py'):
            continue
        k = _key(fname)
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
