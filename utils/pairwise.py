"""
utils/pairwise.py
취약/패치 쌍 구성 및 Pairwise Accuracy 채점.

[파일명 규칙]
  취약 코드: CWE-XXX_test.py / CWE-XXX_01_test.py
  패치 코드: CWE-XXX_patch.py / CWE-XXX_01_patch.py

[폴더 구조 지원]
  - 04_safe_boundary: test=patch 동일 코드 → 쌍 구성 제외
  - 나머지 폴더: test+patch 쌍이 같은 폴더 내에 있어야 함
  - 반환 키: 'folder/stem' 형태 (폴더별 동일 CWE 구분)
    예) legacy_db_derived/CWE-22, regression/CWE-22_01
"""
import os
import re
import glob as _pg
from utils.scoring import ground_truth, score

_SAFE_FOLDER = "04_safe_boundary"
_NO_FOLDER   = "unknown"


def _extract_type(folder_name: str) -> str:
    """폴더명에서 번호 접두사 제거."""
    return re.sub(r"^\d+_", "", folder_name) or _NO_FOLDER


def _pair_key(fname: str) -> str:
    """파일명에서 쌍 키 추출 (폴더 정보 없이 순수 stem만)."""
    base = os.path.basename(fname)
    stem = base[:-3] if base.endswith('.py') else base
    stem = re.sub(r'[_](?:test|patch)\d*$', '', stem, flags=re.IGNORECASE)
    # 쉼표 구분 다중 CWE 정규화
    def _normalize(s):
        def repl(m):
            first = m.group(1)
            rest  = m.group(2).split(',')
            parts = [f"CWE-{first}"] + [f"CWE-{n.strip()}" for n in rest if n.strip()]
            return "_".join(sorted(set(parts)))
        return re.sub(r'CWE-(\d{1,4})((?:,\d{1,4})+)', repl, s, flags=re.IGNORECASE)
    return _normalize(stem)


def build_pairs(test_dir: str) -> dict[str, dict]:
    """
    test_dir 내 파일을 순회하여 vuln/patch 쌍 구성.

    04_safe_boundary 폴더 제외 (test=patch 동일 코드).
    키 형식: 'test_type/CWE-stem' (폴더별 동일 CWE 구분 가능)

    반환:
    {
      "legacy_db_derived/CWE-22": {
        "vuln":  "00_legacy_db_derived/CWE-22_test.py",   # TEST_DIR 기준 relpath
        "patch": "00_legacy_db_derived/CWE-22_patch.py",
        "test_type": "legacy_db_derived"
      }, ...
    }
    """
    # 폴더별 vuln/patch 수집
    folder_vuln:  dict[str, dict[str, str]] = {}  # {folder_key: {stem: relpath}}
    folder_patch: dict[str, dict[str, str]] = {}

    for fpath in _pg.glob(os.path.join(test_dir, "**", "*.py"), recursive=True):
        # safe_boundary 제외
        if _SAFE_FOLDER in fpath.replace("\\", "/"):
            continue

        fname      = os.path.basename(fpath)
        folder_abs = os.path.dirname(fpath)
        folder_rel = os.path.basename(folder_abs)           # '01_regression'
        test_type  = _extract_type(folder_rel)               # 'regression'
        stem       = _pair_key(fname)
        relpath    = os.path.relpath(fpath, test_dir).replace("\\", "/")

        if not stem:
            continue

        if re.search(r'_patch\d*\.py$', fname, re.I):
            folder_patch.setdefault(test_type, {})[stem] = relpath
        elif fname.endswith('.py'):
            folder_vuln.setdefault(test_type, {})[stem] = relpath

    # 폴더 내 쌍 구성
    pairs: dict[str, dict] = {}
    for test_type, vuln_map in folder_vuln.items():
        patch_map = folder_patch.get(test_type, {})
        for stem, vuln_rel in vuln_map.items():
            if stem in patch_map:
                key = f"{test_type}/{stem}"
                pairs[key] = {
                    "vuln":      vuln_rel,
                    "patch":     patch_map[stem],
                    "test_type": test_type,
                }
    return pairs


def score_pair(vuln_pred: str, patch_pred: str,
               vuln_gt: list[str], patch_gt: list[str]) -> str:
    """취약 CWE 정확히 예측 AND 패치 None 판정 → PAIR_TP."""
    ok_vuln  = score(vuln_pred,  vuln_gt)  == "TP"
    ok_patch = score(patch_pred, patch_gt) == "TP"
    return "PAIR_TP" if (ok_vuln and ok_patch) else "PAIR_FP"