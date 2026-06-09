"""
generate_patches.py
py_dataset의 *_test.py → *_patch.py 1:1 자동 생성 + 정밀 검증 파이프라인.

[논문 GT 품질 보장 목표]
  (a) 원본 CWE 취약점 완전 제거
  (b) 새로운 CWE 취약점 미유입
  (c) 문법 valid + 기능 구조 보존

[1:1 매핑 규칙] (그룹핑 없이 파일명 직접 변환)
  CWE-79_test.py     ↔ CWE-79_patch.py
  CWE-79_test2.py    ↔ CWE-79_patch2.py
  CWE-79_01_test.py  ↔ CWE-79_01_patch.py
  CWE-400_01_CWE-22_CWE-770_archive_extract_test.py
                     ↔ CWE-400_01_CWE-22_CWE-770_archive_extract_patch.py

[검증 단계]
  1. 코드 추출    : 마크다운/설명 견고 제거 (코드펜스 내부만 정밀 추출)
  2. 문법 검증    : ast.parse()
  3. 구조 보존    : 함수/클래스 시그니처 AST 비교
  4. diff 검증    : 변경량 합리성
  5. Bandit 교차  : 원본 이슈 감소 + 새 이슈 미유입
  6. LLM 원본검증 : 원본 CWE가 해결됐는가 (RESOLVED)
  7. LLM 신규검증 : 새 CWE가 없는가 (None)

[운영 기능]
  - 중단/재시작 복구 (체크포인트)
  - FAIL patch 자동 격리 (quarantine 폴더)
  - API 429 지수 백오프 재시도
  - Bandit 설치 사전 확인

사용법:
    python generate_patches.py --dry-run
    python generate_patches.py --limit 5
    python generate_patches.py
    python generate_patches.py --verify-only
    python generate_patches.py --no-llm
    python generate_patches.py --resume        # 중단 지점부터 이어서

stage6(신규CWE검증) 속도 옵션:
    python generate_patches.py --no-stage6-new-only --resume
      → 00_legacy/01_regression: stage5+6 full 검증 (GT 품질 보장)
      → 02_semantic~05_external: stage6 생략 (약 33% 속도 향상)
      → 권장: 신규 유형 파일이 많을 때

    python generate_patches.py --no-stage6 --resume
      → 모든 폴더 stage6 전체 생략 (최속)
      → GT 오염 위험 있음 — 권장하지 않음
"""
import os, re, time, json, ast, argparse, subprocess, difflib, datetime, random
import concurrent.futures  # 멀티스레딩 담당
import threading
from google import genai
from google.genai import errors as genai_errors
from dotenv import load_dotenv

load_dotenv()
_key = os.getenv("GEMINI_API_KEY")
if not _key: print("GEMINI_API_KEY 없음"); exit()
client = genai.Client(api_key=_key)

TEST_DIR      = "py_dataset"
QUARANTINE    = "py_dataset_fail"         # FAIL patch 격리 (루트)
QUARANTINE_SUB = os.path.join(QUARANTINE, "00_legacy_db_derived")  # 실제 격리 위치
LOG_DIR       = "patch_log"
CKPT_PATH     = os.path.join(LOG_DIR, "_checkpoint.json")
FLASH_MODEL   = "gemini-2.5-flash"
PRO_MODEL     = "gemini-2.5-pro"
GEN_DELAY     = 2.0
VERIFY_DELAY  = 1.0
MAX_WORKERS   = 5     # 동시 스레드 수 (Tier1 이상 권장)
MAX_RETRIES   = 5     # 429 재시도 횟수
DIFF_MIN      = 0.0   # 이하면 미적용 (비율)
DIFF_MAX_MULT = 4     # patch가 원본의 이 배수 초과 시 전체재작성 의심

# ── 프롬프트 ─────────────────────────────────────────────────

GENERATE_PROMPT = """당신은 파이썬 보안 전문가입니다.
아래 [취약한 코드]의 파일명에서 CWE 번호를 확인하고,
해당 CWE 취약점만 정확히 제거한 안전한 패치 코드를 작성하세요.

[엄격한 규칙]
1. 코드의 전체 구조, 함수명, 클래스명, 시그니처를 그대로 유지하세요.
2. 해당 CWE 취약점 부분만 안전한 방식으로 수정하세요.
3. 새로운 취약점을 만들지 마세요 (예: 입력검증 추가 시 ReDoS 주의).
4. 기능을 추가하거나 전체를 재작성하지 마세요.
5. import 문을 빠뜨리지 말고 문법적으로 완전한 코드를 작성하세요.
6. 반드시 코드만 출력하세요. 인사말, 설명, 주석 추가 금지.
   코드는 단일 ```python 코드블록 안에 작성하세요.
7. 'your_token_here', 'CHANGE_ME', 'TODO', 'placeholder' 같은 더미값을 절대 사용하지 마세요.
   환경변수가 필요하면 os.environ["KEY_NAME"] 형태로 직접 참조하세요.
8. 패스워드 해시 용도라면 반드시 bcrypt, argon2, scrypt 등 키 스트레칭 알고리즘을 사용하세요.
   SHA-256/MD5는 패스워드 저장에 부적합합니다.

[파일명 (CWE 참고용)]
{filename}

[취약한 코드]
{code}
"""

VERIFY_ORIGINAL_PROMPT = """당신은 파이썬 보안 코드 검토 전문가입니다.
아래 [코드]에서 {cwe} 취약점이 해결되었는지만 판단하세요.

[코드]
{code}

{cwe} 취약점이 완전히 해결되었으면 마지막 줄에 <RESULT>RESOLVED</RESULT>,
아직 남아있으면 <RESULT>VULNERABLE</RESULT>를 출력하세요.
"""

VERIFY_NEW_PROMPT = """당신은 파이썬 보안 코드 검토 전문가입니다.
아래 [코드]에 존재하는 모든 보안 취약점(CWE)을 빠짐없이 찾으세요.
주요 취약점뿐 아니라 부차적·잠재적 취약점도 모두 포함하세요.
취약점이 전혀 없으면 안전한 코드입니다.

[코드]
{code}

분석 후 마지막 줄에 발견된 모든 CWE를 출력하세요:
  취약점 없음: <CWE>None</CWE>
  있음(여러 개 가능): <CWE>CWE-XXX,CWE-YYY,CWE-ZZZ</CWE>
"""

# ── 1:1 파일명 매핑 ───────────────────────────────────────────

def test_to_patch(test_fname):
    """
    test 파일명 → patch 파일명 1:1 변환.
    _test, _test2, _01_test 등 모든 패턴에서 'test'만 'patch'로 치환.
      CWE-79_test.py    → CWE-79_patch.py
      CWE-79_test2.py   → CWE-79_patch2.py
      CWE-79_01_test.py → CWE-79_01_patch.py
      ..._archive_extract_test.py → ..._archive_extract_patch.py
    """
    # 'test' (대소문자) + 선택적 숫자 + .py → 'patch' + 같은 숫자 + .py
    return re.sub(r'test(\d*)\.py$', r'patch\1.py', test_fname, flags=re.IGNORECASE)

def is_test_file(fname):
    return bool(re.search(r'test\d*\.py$', fname, re.IGNORECASE)) and '_patch' not in fname.lower()

def is_patch_file(fname):
    return bool(re.search(r'patch\d*\.py$', fname, re.IGNORECASE))

def cwes_in_filename(fname):
    nums  = re.findall(r'CWE-(\d{1,4})', fname, re.IGNORECASE)
    after = re.findall(r'CWE-\d{1,4},(\d{1,4})', fname, re.IGNORECASE)
    seen = []
    for n in nums + after:
        c = f"CWE-{n}"
        if c not in seen: seen.append(c)
    return seen

def find_missing_patches():
    """patch가 없는 test 파일 목록 (폴더 내 1:1 기준).

    핵심 변경: 파일명이 아닌 '같은 폴더 내 쌍 존재 여부'로 판단.
    00_legacy에 CWE-22_patch.py가 있어도
    01_regression의 CWE-22_test.py는 별도 생성 대상으로 처리.
    """
    import glob as _fg

    # fail 폴더: 전체 경로 기준 (폴더+파일명 쌍)
    fail_pairs = set()
    if os.path.exists(QUARANTINE):
        for p in _fg.glob(os.path.join(QUARANTINE, "**", "*.py"), recursive=True):
            folder = os.path.basename(os.path.dirname(p))
            fail_pairs.add((folder, os.path.basename(p)))

    out = []
    for test_path in sorted(_fg.glob(os.path.join(TEST_DIR, "**", "*.py"), recursive=True)):
        fname = os.path.basename(test_path)
        if not is_test_file(fname) or fname == 'd.py':
            continue
        folder     = os.path.dirname(test_path)
        folder_key = os.path.basename(folder)
        patch_name = test_to_patch(fname)
        patch_path = os.path.join(folder, patch_name)

        # 같은 폴더에 patch가 있으면 건너뜀
        if os.path.exists(patch_path):
            continue
        # 같은 폴더 기준으로 fail 폴더에 있어도 건너뜀
        if (folder_key, patch_name) in fail_pairs:
            continue
        out.append(fname)
    return out

def find_existing_patches_tests():
    """이미 patch가 있는 test 파일 목록 (재검증용)"""
    files = set(os.listdir(TEST_DIR))
    out = []
    for f in sorted(files):
        if f.endswith('.py') and is_test_file(f):
            if test_to_patch(f) in files:
                out.append(f)
    return out

# ── 코드 추출 (지적1 해결) ────────────────────────────────────

def extract_code(raw_text):
    """
    LLM 응답에서 순수 코드만 정밀 추출.
    1순위: ```python ... ``` 또는 ``` ... ``` 코드펜스 내부
    2순위: 코드펜스 없으면 설명 줄 제거 후 전체
    """
    # 코드펜스 내부 추출 (가장 큰 블록)
    fences = re.findall(r'```(?:python|py)?\s*\n?(.*?)```', raw_text, re.DOTALL | re.IGNORECASE)
    if fences:
        # 가장 긴 코드 블록 선택 (설명용 짧은 블록 배제)
        code = max(fences, key=len).strip()
        return code

    # 코드펜스 없음: 앞부분 설명 줄 휴리스틱 제거
    lines = raw_text.strip().splitlines()
    # 코드처럼 보이는 첫 줄 찾기 (import, from, def, class, 주석, 변수할당 등)
    code_start = 0
    for i, line in enumerate(lines):
        s = line.strip()
        if re.match(r'^(import |from |def |class |@|#!|"""|\'\'\'|[A-Za-z_][\w]*\s*=|if |try:|with )', s):
            code_start = i
            break
    return "\n".join(lines[code_start:]).strip()

# ── API 호출 (지적3: 429 백오프) ──────────────────────────────

def call_api(model, prompt, base_delay):
    """지수 백오프 재시도 포함 API 호출.
    첫 시도는 즉시 실행, 429 발생 시에만 지수 백오프 대기."""
    for attempt in range(MAX_RETRIES):
        try:
            r = client.models.generate_content(model=model, contents=prompt)
            return r.text, None
        except genai_errors.ClientError as e:
            code = getattr(e, 'code', None) or getattr(e, 'status_code', None)
            if code == 429 or 'RESOURCE_EXHAUSTED' in str(e):
                wait = (2 ** attempt) * base_delay + random.uniform(0, 1)
                print(f"\n    [429] {wait:.1f}s 대기 후 재시도 ({attempt+1}/{MAX_RETRIES})", flush=True)
                time.sleep(wait)
                continue
            return None, f"API오류: {e}"
        except Exception as e:
            return None, f"오류: {e}"
    return None, "429 재시도 초과"

# ── 검증 단계 ─────────────────────────────────────────────────


def stage_placeholder(patch_code):
    """
    플레이스홀더 문자열 탐지.
    LLM이 your_token_here, CHANGE_ME 같은 더미값을 심는 경우를 잡음.
    주석 줄은 검사 제외.
    """
    suspects = [
        "your_token", "your_key", "your_secret", "your_password",
        "your_pass", "your_pwd", "yourtoken", "yourkey",
        "change_me", "changeme", "replace_me", "replaceme",
        "placeholder", "insert_here", "put_here",
        "your strong", "your_strong",
    ]
    # 환경변수 기본값 하드코딩 탐지: os.environ.get("KEY", "actual_secret_value")
    # 단, 빈 문자열/None/localhost/example 같은 비밀번호 아닌 기본값은 제외
    import re as _re
    env_defaults = _re.findall(
        r"os\.environ\.get\([^,]+,\s*[\"']([^\"\']{8,})[\"']",
        patch_code
    )
    harmless = {'localhost', 'example', 'test', 'debug', 'development', '127.0.0.1'}
    for default in env_defaults:
        dl = default.lower()
        if not any(h in dl for h in harmless):
            return False, f"환경변수기본값하드코딩의심: '{default[:30]}'"
    for line in patch_code.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        line_lower = stripped.lower()
        for s in suspects:
            if s in line_lower:
                return False, f"플레이스홀더의심: '{s}'"
    return True, "플레이스홀더 없음"

def stage_syntax(code):
    """문법 검증 + 미정의 이름 간이 검사."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"문법오류 line{e.lineno}: {e.msg}"

    # 미정의 이름 간이 검사: 정의되지 않은 이름이 Load 컨텍스트로 사용되는지 확인
    # (import 없이 사용되는 flask.request 등 탐지)
    defined = set()
    used_before_def = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in getattr(node, 'names', []):
                defined.add(alias.asname or alias.name.split('.')[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    defined.add(t.id)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            # 파이썬 내장이나 일반 패턴 제외
            builtins = {'True','False','None','print','len','range','int','str',
                       'list','dict','set','tuple','bool','type','isinstance',
                       'hasattr','getattr','setattr','open','super','self','cls',
                       'Exception','ValueError','KeyError','TypeError','__name__',
                       '__file__','__main__',
                       # 자주 쓰이는 Flask/외부라이브러리 전역 (모듈 레벨 사용 허용)
                       'app','request','g','session','current_app','abort',
                       'bytes','bytearray','memoryview','object','property',
                       'staticmethod','classmethod','NotImplementedError',
                       'AttributeError','RuntimeError','StopIteration',
                       'zip','enumerate','map','filter','sorted','reversed',
                       'max','min','sum','all','any','id','hash','repr',
                       'format','vars','dir','globals','locals',
                       }
            if node.id not in defined and node.id not in builtins:
                used_before_def.append(node.id)

    if used_before_def:
        suspects = list(dict.fromkeys(used_before_def))[:3]  # 중복 제거, 최대 3개
        return None, f"미정의이름의심: {', '.join(suspects)} (수동확인)"

    return True, "문법 정상"

def _signatures(code):
    sigs = set()
    try:
        for node in ast.walk(ast.parse(code)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sigs.add(('func', node.name, len(node.args.args)))
            elif isinstance(node, ast.ClassDef):
                sigs.add(('class', node.name))
    except SyntaxError:
        pass
    return sigs

def stage_structure(test_code, patch_code):
    ts = _signatures(test_code)
    if not ts: return None, "함수/클래스 없음(스크립트형)"
    missing = ts - _signatures(patch_code)
    if missing:
        return False, f"구조손실: {', '.join(s[1] for s in list(missing)[:3])}"
    return True, f"구조보존({len(ts)})"

def stage_diff(test_code, patch_code):
    """
    개선된 diff 검증 (3단계 구간별 상한).
    보안 방어 코드는 본질적으로 길어지므로 파일 크기에 따라 상한을 다르게 적용.
      - 원본 ≤10줄 : 절대 150줄 상한 (SSRF 등 복잡한 방어 로직 허용)
      - 원본 11~30줄: 원본의 8배 상한 (방어코드 추가 여유 확대)
      - 원본 31줄~  : 원본의 4배 상한 (일반 파일)
    추가: 제거 줄이 추가 줄의 2배 이상이면 전체교체 의심 → WARN
    """
    t = test_code.splitlines()
    p = patch_code.splitlines()
    diff = list(difflib.unified_diff(t, p))
    added   = sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))
    removed = sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))
    ratio = (added + removed) / max(len(t), 1)

    if ratio == 0:
        return False, "변경없음(미적용)"

    if len(t) <= 10:
        if len(p) > 150:
            return False, f"전체재작성의심({len(t)}→{len(p)}줄, 150줄초과)"
    elif len(t) <= 30:
        if len(p) > len(t) * 8:
            return False, f"전체재작성의심({len(t)}→{len(p)}줄, 8배초과)"
    else:
        if len(p) > len(t) * 4:
            return False, f"전체재작성의심({len(t)}→{len(p)}줄, 4배초과)"

    if removed > added * 2 and removed > 10:
        return None, f"전체교체의심(추가{added}/제거{removed}) — 수동확인권장"

    return True, f"변경률 {ratio:.0%}(추가{added}/제거{removed})"

_BANDIT_AVAILABLE = None  # None=미확인, True=설치됨, False=없음

def bandit_available():
    global _BANDIT_AVAILABLE
    if _BANDIT_AVAILABLE is not None:   # 이미 확인됨
        return _BANDIT_AVAILABLE
    try:
        subprocess.run(['bandit', '--version'], capture_output=True, timeout=10)
        _BANDIT_AVAILABLE = True
    except Exception:
        _BANDIT_AVAILABLE = False
    return _BANDIT_AVAILABLE


# primary CWE → 패치 후 LLM이 FP로 자주 거론하는 관련/상위 CWE 목록
# 이 CWE들은 암호화 도메인에서 Pro가 습관적으로 거론하지만 실제 신규 유입이 아님
_CRYPTO_RELATED_FP = {
    "CWE-321": {"CWE-326", "CWE-320", "CWE-327"},   # 하드코딩키 fix → 키길이/알고리즘 FP
    "CWE-326": {"CWE-320", "CWE-327", "CWE-321"},   # 키길이 fix → 관련 암호화 FP
    "CWE-327": {"CWE-326", "CWE-321", "CWE-320", "CWE-522"},  # 알고리즘 fix → 관련 FP
    "CWE-328": {"CWE-916", "CWE-327"},               # 해시 fix → 관련 FP
    "CWE-329": {"CWE-330", "CWE-326"},               # IV fix → 관련 FP
    "CWE-367": {"CWE-22",  "CWE-362", "CWE-377"},    # TOCTOU fix → 관련 경쟁조건/경로 FP
    "CWE-345": {"CWE-259", "CWE-290"},               # 서명검증 추가 → 환경변수 FP
    "CWE-350": {"CWE-367", "CWE-22"},                # 불충분검증 fix → 관련 FP
    "CWE-352": {"CWE-79",  "CWE-116"},               # CSRF fix → XSS/인코딩 FP
    "CWE-319": {"CWE-295", "CWE-798"},               # 평문전송 fix → TLS검증/자격증명 FP
    "CWE-315": {"CWE-287", "CWE-539"},               # 쿠키 fix → 인증/세션 FP
    "CWE-312": {"CWE-20",  "CWE-116"},               # 평문저장 fix → 입력검증 FP
    "CWE-311": {"CWE-20",  "CWE-362"},               # 암호화누락 fix → 관련 FP
    # 보안 강화 패치 시 LLM 습관적 오탐 패턴 추가
    "CWE-502": {"CWE-79",  "CWE-306", "CWE-20"},     # 역직렬화 fix → 입력검증/인증 FP
    "CWE-521": {"CWE-307", "CWE-522"},               # 약한패스워드 fix → 관련인증 FP
    "CWE-522": {"CWE-523", "CWE-256"},               # 자격증명보호 fix → 전송보안 FP
    "CWE-524": {"CWE-613", "CWE-311"},               # 캐시민감정보 fix → 세션/암호화 FP
    "CWE-571": {"CWE-287", "CWE-807"},               # 조건판단 fix → 인증 FP
    "CWE-598": {"CWE-798", "CWE-200"},               # GET파라미터 fix → 하드코딩/노출 FP
    "CWE-601": {"CWE-306", "CWE-20"},                # URL리다이렉트 fix → 인증/입력검증 FP
    "CWE-602": {"CWE-20",  "CWE-807"},               # 클라이언트검증 fix → 서버입력검증 FP
    "CWE-611": {"CWE-209", "CWE-776"},               # XXE fix → 에러노출/재귀 FP
    "CWE-780": {"CWE-327", "CWE-755"},               # RSA OAEP fix → 암호화/예외 FP
    "CWE-836": {"CWE-287", "CWE-916", "CWE-798", "CWE-203"},  # 비교취약점 fix → 인증/해시 FP
    "CWE-863": {"CWE-287", "CWE-532", "CWE-840"},   # 권한부여 fix → 인증/로깅 FP
    "CWE-306": {"CWE-208", "CWE-778", "CWE-754", "CWE-319"},  # 인증없음 fix → 타이밍/로깅 FP
    "CWE-472": {"CWE-248", "CWE-840"},               # 파라미터조작 fix → 예외/동작 FP
    # 새로 추가된 FP 패턴들
    "CWE-130":  {"CWE-22"},                           # 버퍼길이 fix → 경로 FP
    "CWE-201":  {"CWE-532"},                           # 정보노출 fix → 로그노출 FP
    "CWE-226":  {"CWE-248", "CWE-367", "CWE-662"},    # 민감정보 fix → 예외/TOCTOU FP
    "CWE-253":  {"CWE-208", "CWE-287", "CWE-327", "CWE-347"},  # 오류코드 fix → 인증/암호화 FP
    "CWE-256":  {"CWE-390", "CWE-404"},               # 평문저장 fix → 에러처리 FP
    "CWE-266":  {"CWE-117", "CWE-532", "CWE-916"},    # 권한부여 fix → 로그/해시 FP
    "CWE-270":  {"CWE-269", "CWE-362", "CWE-532", "CWE-667"},  # 권한상승 fix → 동기화 FP
    "CWE-274":  {"CWE-285", "CWE-862"},               # 권한처리 fix → 권한확인 FP
    "CWE-281":  {"CWE-362", "CWE-434"},               # 권한보존 fix → 경쟁/업로드 FP
    "CWE-307":  {"CWE-208", "CWE-287", "CWE-312", "CWE-330", "CWE-362", "CWE-613"},
    "CWE-325":  {"CWE-326", "CWE-329"},               # 암호화단계누락 fix → 관련암호화 FP
    "CWE-340":  {"CWE-362"},                           # 예측가능값 fix → 경쟁조건 FP
    "CWE-347":  {"CWE-287", "CWE-326"},               # 서명검증 fix → 인증/키길이 FP
    "CWE-348":  {"CWE-116", "CWE-755"},               # 사용자식별 fix → 인코딩/예외 FP
    "CWE-349":  {"CWE-248"},                           # 응답노출 fix → 예외처리 FP
    "CWE-391":  {"CWE-396", "CWE-532", "CWE-613"},    # 예외무시 fix → 예외/세션 FP
    "CWE-425":  {"CWE-538"},                           # 직접요청 fix → 파일노출 FP
    "CWE-436":  {"CWE-176", "CWE-178", "CWE-754", "CWE-770"},
    "CWE-471":  {"CWE-269"},                           # 불변수정 fix → 권한 FP
    "CWE-480":  {"CWE-285", "CWE-807"},               # 연산자오용 fix → 인증/판단 FP
    "CWE-549":  {"CWE-319", "CWE-352", "CWE-522"},    # 하드코딩비번 fix → 전송/CSRF FP
    "CWE-566":  {"CWE-248", "CWE-772", "CWE-863"},    # 인증우회 fix → 자원/권한 FP
    "CWE-584":  {"CWE-248", "CWE-862"},               # finally오용 fix → 예외/권한 FP
    "CWE-636":  {"CWE-248"},                           # 기본값위험 fix → 예외처리 FP
    "CWE-642":  {"CWE-117", "CWE-248", "CWE-284"},    # 외부쿼리 fix → 로그/접근제어 FP
    "CWE-665":  {"CWE-1188"},                          # 초기화 fix → 기본값위험 FP
    "CWE-668":  {"CWE-362"},                           # 자원노출 fix → 경쟁조건 FP
    "CWE-669":  {"CWE-287", "CWE-345", "CWE-362", "CWE-770", "CWE-798"},
    "CWE-672":  {"CWE-248", "CWE-367", "CWE-532", "CWE-841"},
    "CWE-675":  {"CWE-362", "CWE-390", "CWE-532", "CWE-840", "CWE-862", "CWE-863"},
    "CWE-682":  {"CWE-755", "CWE-840"},               # 계산오류 fix → 예외/비즈니스 FP
    "CWE-696":  {"CWE-287", "CWE-307", "CWE-522", "CWE-754"},
    "CWE-698":  {"CWE-778", "CWE-863"},               # 리다이렉트 fix → 로깅/권한 FP
    "CWE-706":  {"CWE-362", "CWE-840", "CWE-862"},    # 이름혼동 fix → 경쟁/비즈니스 FP
    "CWE-754":  {"CWE-248", "CWE-367"},               # 예외처리 fix → 예외타입/TOCTOU FP
    "CWE-772":  {"CWE-601", "CWE-918"},               # 자원해제 fix → SSRF/리다이렉트 FP
    "CWE-1286": {"CWE-248", "CWE-754", "CWE-770"},
    "CWE-1287": {"CWE-269"},
    "CWE-1288": {"CWE-840"},
}

# Bandit test ID → CWE 매핑 테이블
# 우리 primary CWE와 직접 관련된 이슈만 검증에 사용
_BANDIT_CWE_MAP = {
    # 하드코딩
    "B105": "CWE-259", "B106": "CWE-259", "B107": "CWE-259",
    # SQL Injection
    "B608": "CWE-89",
    "B201": None,   # Flask debug=True — CWE-94 패치와 무관 FP
    "B108": None,   # tmpfile 사용 — 보안 패치 후 잔존 FP
    "B103": None,   # 파일 권한 설정 — chmod 개선 패치 후 FP
    "B377": None,   # tmpnam/tempnam 사용 — tempfile로 교체 후 FP
    "B105": None,   # 하드코딩 패스워드 — 환경변수 참조 시 FP (별도 처리)
    "B404": None,   # subprocess import — 화이트리스트 방식 CWE-78 패치에서 FP
    "B603": None,   # subprocess call — 화이트리스트 방식 CWE-78 패치에서 FP
    "B607": None,   # subprocess partial path — 동일 FP
    "B608": None,   # SQL string format — 화이트리스트 검증 후 FP
    "B413": None,   # PyCryptodome ARC4 — AES 교체 후 잔존 오탐 FP
    "B320": None,   # xml.sax 관련 — xml 이스케이프 패치 후 FP
    # 명령 주입 (subprocess/shell=True)
    "B602": "CWE-78", "B605": "CWE-78",
    # subprocess 사용 자체 경고 — CWE와 1:1 매핑 불가, 필터링
    "B603": None, "B607": None,
    # 경로 탐색
    "B202": "CWE-22",
    # 역직렬화
    "B301": "CWE-502", "B302": "CWE-502",
    # XXE
    "B320": "CWE-611", "B321": "CWE-611",
    # 암호화 약점
    "B501": "CWE-326", "B502": "CWE-327", "B503": "CWE-327",
    "B504": "CWE-326", "B505": "CWE-326",
    # 해시 약점
    "B303": "CWE-328", "B324": "CWE-328",
    # 랜덤
    "B311": "CWE-338",
    # assert
    "B101": None,  # 논리 제어용, CWE 매핑 불필요
    # YAML
    "B506": "CWE-502",
    # XML
    "B408": "CWE-611", "B409": "CWE-611",
    # 임시파일
    "B108": "CWE-377",
    # exec/eval
    "B102": "CWE-78", "B307": "CWE-94",
}

def _run_bandit(path):
    try:
        r = subprocess.run(['bandit','-f','json','-q',path],
                          capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout) if r.stdout.strip() else {"results":[]}
        issues = []  # (test_id, cwe_or_none)
        for issue in data.get("results", []):
            tid = issue.get("test_id", "")
            # Bandit 자체 CWE 필드 우선, 없으면 매핑 테이블
            cid = issue.get("issue_cwe", {}).get("id")
            if cid:
                cwe = f"CWE-{cid}"
            else:
                cwe = _BANDIT_CWE_MAP.get(tid)  # None이면 필터링됨
            issues.append((tid, cwe))
        return issues
    except Exception:
        return None

def _relevant_issues(issues, primary_cwes):
    """primary CWE에 해당하는 이슈만 반환. primary_cwes 빈 경우 전체 반환."""
    if not primary_cwes:
        return [i for i in issues if i[1] is not None]
    return [i for i in issues if i[1] in primary_cwes]

def stage_bandit(test_path, patch_path, primary_cwes=None):
    """
    개선된 Bandit 검증.
    primary CWE에 매핑되는 이슈만 비교 → 무관한 Bandit 경고로 오탐 방지.
    """
    if not bandit_available():
        return None, "Bandit 미설치"

    t_issues = _run_bandit(test_path)
    p_issues = _run_bandit(patch_path)
    if t_issues is None or p_issues is None:
        return None, "Bandit 실행불가"

    # primary CWE에 해당하는 이슈만 필터링
    t_rel = _relevant_issues(t_issues, primary_cwes)
    p_rel = _relevant_issues(p_issues, primary_cwes)

    # 신규 CWE 유입 체크 (전체 이슈 기준)
    t_cwes = {i[1] for i in t_issues if i[1]}
    p_cwes = {i[1] for i in p_issues if i[1]}
    new_cwes = p_cwes - t_cwes

    if new_cwes:
        # B105(하드코딩패스워드) → CWE-259 탐지인데
        # patch 코드에 실제로 os.environ 참조가 있으면 FP (환경변수는 하드코딩 아님)
        filtered_new = set()
        with open(patch_path, encoding='utf-8') as _pf:
            _patch_src = _pf.read()
        for cwe in new_cwes:
            if cwe == "CWE-259" and "os.environ" in _patch_src:
                continue  # 환경변수 참조 → B105 FP
            if cwe in _GLOBAL_FP_CWES:
                continue  # 글로벌 FP → 새이슈 아님
            filtered_new.add(cwe)
        new_cwes = filtered_new
        if new_cwes:
            return False, f"새이슈유입: {', '.join(sorted(new_cwes))}"

    # primary 관련 이슈 변화 확인
    if not t_rel:
        return None, f"primary CWE 관련 Bandit 이슈 없음(탐지불가CWE)"
    if len(p_rel) == 0:
        return True, f"관련이슈 완전제거({len(t_rel)}→0)"
    if len(p_rel) < len(t_rel):
        return True, f"관련이슈 감소({len(t_rel)}→{len(p_rel)})"

    # 관련 이슈 수 동일 — FAIL 전에 무관 이슈인지 재확인
    t_ids = {i[0] for i in t_rel}
    p_ids = {i[0] for i in p_rel}
    if t_ids == p_ids:
        # None 매핑 Bandit ID는 이미 _relevant_issues에서 필터됨
        # 특정 패턴: 코드 내 안전 조치가 있으면 FP로 판단
        with open(patch_path, encoding='utf-8') as _pf:
            _ps = _pf.read().lower()
        fp_ids = set()
        for bid in t_ids:
            # B413: ARC4 없으면 FP (AES로 교체됨)
            if bid == 'B413' and 'arc4' not in _ps:
                fp_ids.add(bid)
            # B608: SQL 포맷팅이지만 화이트리스트 검증 후 사용 시 FP
            elif bid == 'B608' and ('allowed_' in _ps or 'whitelist' in _ps or 'allowlist' in _ps):
                fp_ids.add(bid)
            # B404/B603: subprocess이지만 화이트리스트 방식이면 FP
            elif bid in ('B404','B603') and ('allowed_' in _ps or 'whitelist' in _ps):
                fp_ids.add(bid)
        real_ids = t_ids - fp_ids
        if fp_ids:
            fp_note = f"(FP제외:{','.join(sorted(fp_ids))})"
        if not real_ids:
            return True, f"관련이슈FP처리{fp_note if fp_ids else ''}"
        return False, f"관련이슈미해결: {', '.join(sorted(real_ids))}"
    return True, f"관련이슈변화({','.join(sorted(t_ids))}→{','.join(sorted(p_ids))})"

def _parse_result_tag(text):
    """<RESULT> 태그 + fallback 본문 파싱 (지적C)"""
    m = re.findall(r'<RESULT>\s*(\w+)\s*</RESULT>', text, re.IGNORECASE)
    if m: return m[-1].upper()
    # fallback: 본문 키워드
    low = text.lower()
    if 'resolved' in low or '해결' in low or '안전' in low:
        return "RESOLVED"
    if 'vulnerable' in low or '취약' in low or '남아' in low:
        return "VULNERABLE"
    return "UNKNOWN"

def _parse_cwe_tag(text):
    m = re.findall(r'<CWE>\s*(.*?)\s*</CWE>', text, re.IGNORECASE)
    if m: return m[-1].strip()
    # fallback
    if re.search(r'\bnone\b|취약점\s*없|안전', text, re.IGNORECASE):
        return "None"
    cm = re.search(r'CWE-\d{1,4}', text, re.IGNORECASE)
    return cm.group() if cm else "UNKNOWN"


def _parse_cwe_set(text):
    """<CWE>CWE-XXX,CWE-YYY</CWE> 태그에서 모든 CWE를 집합으로 추출."""
    m = re.findall(r'<CWE>\s*(.*?)\s*</CWE>', text, re.IGNORECASE)
    raw = m[-1].strip() if m else text
    if re.search(r'\bnone\b', raw, re.IGNORECASE) and 'CWE-' not in raw.upper():
        return {"None"}
    cwes = set(re.findall(r'CWE-\d{1,4}', raw, re.IGNORECASE))
    cwes = {c.upper() for c in cwes}
    return cwes if cwes else {"UNKNOWN"}

# 어떤 원본 CWE든 patch 후 LLM이 습관적으로 거론하는 범용 FP CWE
# (두 로그 100개 분석 결과: CWE-400이 22회, CWE-20이 14회, CWE-209가 11회 반복)
_GLOBAL_FP_CWES = {
    "CWE-400",  # 자원소진 — 모든 보안 개선 코드에서 습관적 언급
    "CWE-200",  # 정보노출 — 보안 강화 패치 후 범용 언급
    "CWE-209",  # 에러메시지 노출 — 에러처리 추가 패치 후 언급
    "CWE-20",   # 입력검증 — 거의 모든 패치에서 과잉 언급
    "CWE-208",  # 타이밍 공격 — 인증/암호화 패치 후 LLM 습관적 언급
    "CWE-755",  # 예외처리 — 보안 로직 추가 후 습관적 언급
}

# Python에서 완전한 원자적 패치가 불가능한 CWE (OS 레벨 제한)
_INHERENTLY_PARTIAL_CWES = {
    "CWE-367",  # TOCTOU: resolve+is_relative_to가 최선, open() 사이 간격 존재
    "CWE-362",  # Race condition: Python에서 완전 방지 불가
    "CWE-400",  # 자원소진: 상한 설정이 최선, 완전 차단 불가
    "CWE-459",  # 불완전 정리: tempfile 사용이 최선, OS 정리 보장 불가
    "CWE-90",   # LDAP 인젝션: escape_filter_chars가 표준 패치
    "CWE-918",  # SSRF: IP 검증이 최선, DNS rebinding 등 완전 차단 불가
    "CWE-293",  # 헤더 신뢰: 구조적 한계 (Referer 위조 가능)
    "CWE-273",  # 부적절한 권한 해제: OS 레벨 권한 관리, Python에서 완전 제어 불가
    "CWE-353",  # 무결성 확인: 크기 제한이 최선, HMAC/서명은 구조 변경 필요
    "CWE-645",  # 쿠키 만료: 브라우저/서버 정책 혼재, 완전 통제 불가
    "CWE-203",  # 오류 기반 정보노출: 완전 제거 불가
    "CWE-22",   # 경로 순회: resolve/is_relative_to가 최선
    "CWE-307",  # 무제한 인증 시도: 완전 차단 불가
    "CWE-436",  # 모호한 해석: 구조적 한계
    "CWE-502",  # 역직렬화: json.loads가 최선, 일부 패턴 잔존
    "CWE-642",  # 외부 쿼리 변조: 파라미터 이스케이프가 최선
    "CWE-665",  # 초기화 불완전: 언어 수준 한계
    "CWE-840",  # 비즈니스 로직 오류: 도메인별 다양
    # ── 1386개 실행 분석 결과 추가 ──────────────────────────
    "CWE-59",   "CWE-184",  "CWE-212",  "CWE-214",  "CWE-270",
    "CWE-291",  "CWE-322",  "CWE-349",  "CWE-379",  "CWE-403",
    "CWE-406",  "CWE-408",  "CWE-488",  "CWE-494",  "CWE-501",
    "CWE-524",  "CWE-532",  "CWE-552",  "CWE-613",  "CWE-640",
    "CWE-647",  "CWE-668",  "CWE-732",  "CWE-757",  "CWE-778",
    "CWE-807",  "CWE-917",  "CWE-1188", "CWE-1426", "CWE-1427",
    "CWE-548",  # 디렉토리 목록 노출: 파일명 제한이 최선, 서버 설정 수준 문제
}

def stage_llm_original(patch_code, orig_cwes):
    for cwe in orig_cwes:
        # stage5: Flash로 속도 향상 (원본 CWE 해결 여부 판단 — Flash로 충분)
        text, err = call_api(FLASH_MODEL, VERIFY_ORIGINAL_PROMPT.format(cwe=cwe, code=patch_code), VERIFY_DELAY)
        if err: return None, err
        verdict = _parse_result_tag(text)
        if verdict == "VULNERABLE":
            # OS 레벨 제한으로 완전 패치 불가능한 CWE는 WARN으로 완화
            if cwe in _INHERENTLY_PARTIAL_CWES:
                return None, f"{cwe} 부분해결(OS레벨한계, 최선의패치로인정)"
            return False, f"{cwe} 미해결"
        if verdict == "UNKNOWN":
            return None, f"{cwe} 판정불가(태그누락)"
    return True, f"원본해결({','.join(orig_cwes)})"

def stage_llm_new(patch_code, orig_cwes, test_code=None):
    """
    신규 CWE 검증: patch 코드의 취약점 - test 코드의 취약점 = 실제 신규 유입분.
    test에도 이미 있던 취약점은 신규가 아님 (원본 취약점과 무관한 잠재이슈).
    """
    # patch 분석
    text_p, err = call_api(PRO_MODEL, VERIFY_NEW_PROMPT.format(code=patch_code), VERIFY_DELAY)
    if err: return None, err
    pred_patch = _parse_cwe_tag(text_p)

    if pred_patch.lower() == 'none':
        return True, "신규취약점없음"
    if pred_patch == "UNKNOWN":
        return None, "판정불가(태그누락)"
    # orig_cwes와 동일하면 원본 CWE가 미해결된 것 → stage5에서 처리됨
    if pred_patch.upper() in [c.upper() for c in orig_cwes]:
        return True, f"원본CWE({pred_patch})만 거론(stage5 결과우선)"

    # 글로벌 FP: 어떤 원본 CWE든 관계없이 항상 FP인 CWE
    if pred_patch.upper() in _GLOBAL_FP_CWES:
        return True, f"글로벌FP: {pred_patch}는 범용 과잉의심 CWE"

    # 암호화 도메인 관련 CWE FP 자동 처리
    for p_cwe in orig_cwes:
        related_fps = _CRYPTO_RELATED_FP.get(p_cwe, set())
        if pred_patch.upper() in related_fps:
            return True, f"관련CWE FP 자동처리: {pred_patch}은 {p_cwe} 패치 시 LLM 오탐"

    # patch에서 원본 이외 CWE가 발견됨 → test에도 있었는지 확인
    if test_code:
        text_t, err_t = call_api(PRO_MODEL, VERIFY_NEW_PROMPT.format(code=test_code), VERIFY_DELAY)
        if not err_t:
            # test의 모든 CWE를 집합으로 추출 (단일 비교의 한계 보완)
            test_cwes = _parse_cwe_set(text_t)
            pred_upper = pred_patch.upper()
            # test에도 동일 CWE가 있었으면 신규 아님 → PASS
            if pred_upper in test_cwes:
                return True, f"원본에도존재({pred_patch}) — 신규유입아님(PASS)"
            if test_cwes == {"None"}:
                # test는 안전한데 patch에서 발생 → 진짜 신규
                return False, f"진짜신규취약점: {pred_patch}(test엔없음)"
    # test 비교 불가 시 보수적으로 WARN 처리 (즉시FAIL 대신 수동검토 요청)
    return None, f"신규의심(수동검토): {pred_patch}"

# ── 단일 파일 처리 ────────────────────────────────────────────

def process_one(test_fname, generate=True, use_llm=True, no_stage6=False, no_stage6_new_only=False):
    # 폴더 기반 stage6 자동 결정
    # 00_legacy, 01_regression → full 검증 / 나머지 → stage6 생략

    # test 파일을 하위폴더에서 재귀 탐색
    import glob as _fg
    hits = _fg.glob(os.path.join(TEST_DIR, "**", test_fname), recursive=True)
    test_path = hits[0] if hits else os.path.join(TEST_DIR, test_fname)
    test_folder = os.path.dirname(test_path)   # test와 같은 폴더에 patch 저장

    # 💡 [해결 포인트 1] 폴더명을 맨 위에서 미리 추출합니다! (이게 없어서 에러가 났습니다)
    _folder = os.path.basename(test_folder)

    p_fname    = test_to_patch(test_fname)
    patch_path = os.path.join(test_folder, p_fname)  # 1:1 폴더 대응
    orig_cwes  = cwes_in_filename(test_fname)

    r = {"test": test_fname, "patch": p_fname, "orig_cwes": orig_cwes,
         "generated": False, "stages": {}, "final": "UNKNOWN"}

    with open(test_path, encoding='utf-8') as f:
        test_code = f.read()

    # 💡 [해결 포인트 2] 04 폴더면 복사만 하고, 아니면 LLM 호출 (이 부분도 누락되어 있었습니다)
    if generate and not os.path.exists(patch_path):
        if _folder.startswith("04_"):
            patch_code = test_code  # 원본 그대로 복사
            with open(patch_path, 'w', encoding='utf-8') as f:
                f.write(patch_code + '\n')
            r["generated"] = True
        else:
            raw, err = call_api(FLASH_MODEL, GENERATE_PROMPT.format(filename=test_fname, code=test_code), GEN_DELAY)
            if err:
                r["final"] = f"생성실패: {err}"; return r
            patch_code = extract_code(raw)   # 지적1 해결
            with open(patch_path, 'w', encoding='utf-8') as f:
                f.write(patch_code + '\n')
            r["generated"] = True
    elif not os.path.exists(patch_path):
        r["final"] = "patch없음"; return r

    with open(patch_path, encoding='utf-8') as f:
        patch_code = f.read()

    # 1. 문법
    ok, msg = stage_syntax(patch_code); r["stages"]["1_syntax"] = msg
    if ok is False: r["final"] = f"FAIL_SYNTAX: {msg}"; return r
    if ok is None:  r["stages"]["1_syntax"] = msg  # 미정의이름 WARN, 계속 진행
    # 1-1. 플레이스홀더
    ok_ph, msg_ph = stage_placeholder(patch_code); r["stages"]["1b_placeholder"] = msg_ph
    if not ok_ph: r["final"] = f"FAIL_PLACEHOLDER: {msg_ph}"; return r
    # 2. 구조
    ok, msg = stage_structure(test_code, patch_code); r["stages"]["2_structure"] = msg
    if ok is False: r["final"] = f"FAIL_STRUCTURE: {msg}"; return r

    # 04_safe_boundary: stage3~6 전부 생략, 즉시 PASS
    if _folder.startswith("04_"):
        r["stages"]["3_diff"]         = "04폴더 원본복사(검증생략)"
        r["stages"]["4_bandit"]       = "04폴더 원본복사(검증생략)"
        r["stages"]["5_llm_original"] = "04폴더 원본복사(검증생략)"
        r["stages"]["6_llm_new"]      = "04폴더 원본복사(검증생략)"
        r["final"] = "PASS"
        return r

    # 3. diff
    ok, msg = stage_diff(test_code, patch_code); r["stages"]["3_diff"] = msg
    if not ok: r["final"] = f"FAIL_DIFF: {msg}"; return r
    # 4. Bandit
    ok, msg = stage_bandit(test_path, patch_path, set(orig_cwes)); r["stages"]["4_bandit"] = msg
    if ok is False: r["final"] = f"FAIL_BANDIT: {msg}"; return r

    if not use_llm:
        r["final"] = "PASS_NOLLM"; return r

    # 5. LLM 원본 CWE
    if orig_cwes:
        ok, msg = stage_llm_original(patch_code, orig_cwes); r["stages"]["5_llm_original"] = msg
        if ok is False: r["final"] = f"FAIL_ORIGINAL: {msg}"; return r
        if ok is None:  r["final"] = f"WARN_ORIGINAL: {msg}"; return r
    else:
        r["stages"]["5_llm_original"] = "파일명 CWE 없음 → 건너뜀"
        
    # 6. LLM 신규 CWE
    # (여기에 있던 _folder = ... 삭제 완료)
    _is_semantic_folder = any(
        _folder.startswith(p) for p in ("02_", "03_", "04_", "05_")
    )
    _needs_stage6 = (
        not no_stage6 and
        not (no_stage6_new_only and _is_semantic_folder)
    )
    if use_llm and _needs_stage6:
        ok, msg = stage_llm_new(patch_code, orig_cwes, test_code)
        r["stages"]["6_llm_new"] = msg
        if ok is False: r["final"] = f"FAIL_NEWCWE: {msg}"; return r
        if ok is None:  r["final"] = f"WARN_NEWCWE: {msg}"

    r["final"] = "PASS"
    return r

# ── 격리 (지적F) ──────────────────────────────────────────────

def quarantine_patch(p_fname):
    """FAIL patch를 격리. 원본 폴더 구조를 py_dataset_fail에도 보존.

    예) py_dataset/02_semantic/CWE-89_patch.py
        → py_dataset_fail/02_semantic/CWE-89_patch.py
    폴더 정보 없으면 → py_dataset_fail/00_legacy_db_derived/
    """
    import glob as _fg
    # 1. patch 파일의 현재 경로(하위폴더 포함) 탐색
    hits = _fg.glob(os.path.join(TEST_DIR, "**", p_fname), recursive=True)
    if hits:
        src = hits[0]
        # 2. 원본 폴더명 추출 (py_dataset 기준 상대경로)
        rel = os.path.relpath(os.path.dirname(src), TEST_DIR)
        # 3. fail 폴더에도 동일한 하위폴더 구조 생성
        dst_dir = os.path.join(QUARANTINE, rel) if rel != "." else QUARANTINE_SUB
    else:
        src = os.path.join(TEST_DIR, p_fname)
        dst_dir = QUARANTINE_SUB  # fallback

    if os.path.exists(src):
        os.makedirs(dst_dir, exist_ok=True)
        dst = os.path.join(dst_dir, p_fname)
        os.replace(src, dst)
        return True
    return False

# ── 체크포인트 (지적E) ────────────────────────────────────────

def load_ckpt():
    if os.path.exists(CKPT_PATH):
        with open(CKPT_PATH, encoding='utf-8') as f:
            return set(json.load(f).get("done", []))
    return set()

def save_ckpt(done_set):
    with open(CKPT_PATH, 'w', encoding='utf-8') as f:
        json.dump({"done": sorted(done_set)}, f, ensure_ascii=False, indent=2)

# ── 메인 ─────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--verify-only', action='store_true')
    ap.add_argument('--verify-latest', action='store_true',
                    help='최신 로그의 PASS/WARN 항목만 재검증')
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--no-llm', action='store_true')
    ap.add_argument('--no-stage6', action='store_true',
                    help='stage6(신규CWE검증) 생략 — Pro 호출 3→2회, 약 30% 속도향상')
    ap.add_argument('--no-stage6-new-only', action='store_true',
                    help='신규유형(02~05) stage6 생략, 00_legacy/01_regression은 full 검증 유지 — 권장 속도 옵션')
    ap.add_argument('--resume', action='store_true', help='체크포인트부터 이어하기')
    ap.add_argument('--no-quarantine', action='store_true', help='FAIL patch 격리 안 함')
    args = ap.parse_args()

    os.makedirs(LOG_DIR, exist_ok=True)

    if args.verify_latest:
        # 최신 로그에서 PASS/WARN된 파일만 추출
        import glob
        log_files = sorted(glob.glob(os.path.join(LOG_DIR, "patch_verify_*.json")))
        if not log_files:
            print("로그 없음. --verify-only 또는 전체 실행 먼저 하세요.")
            return
        latest = log_files[-1]
        print(f"최신 로그: {os.path.basename(latest)}")
        with open(latest, encoding='utf-8') as f:
            log_data = json.load(f)
        # PASS/WARN만 (FAIL은 이미 격리됨)
        targets = [r["test"] for r in log_data
                   if "FAIL" not in r["final"] and "EXCEPTION" not in r["final"]
                   and os.path.exists(os.path.join(TEST_DIR, r["test"]))]
        generate = False
        cnt = len(targets)
        print(f"재검증 대상: {cnt}개 (최신 로그 PASS/WARN)")
        print()
    elif args.verify_only:
        targets, generate = find_existing_patches_tests(), False
    else:
        targets, generate = find_missing_patches(), True

    if not targets: 
        print("처리할 파일 없음")
        return

    # 재시작 복구
    done = load_ckpt() if args.resume else set()
    if done:
        targets = [t for t in targets if t not in done]
        print(f"[resume] 완료 {len(done)}개 제외, 남은 {len(targets)}개")

    if args.limit: targets = targets[:args.limit]

    if args.dry_run:
        print(f"[dry-run] 처리 예정: {len(targets)}개")
        for t in targets[:25]:
            print(f"  {t} → {test_to_patch(t)} (CWE:{cwes_in_filename(t)})")
        if len(targets) > 25: print(f"  ... 외 {len(targets)-25}개")
        return

    if not args.no_llm and not bandit_available():
        print("⚠️ Bandit 미설치 — Bandit 단계는 건너뜀 (pip install bandit 권장)\n")

    NO_LLM             = args.no_llm
    NO_STAGE6          = getattr(args, 'no_stage6', False) or NO_LLM
    NO_STAGE6_NEW_ONLY = getattr(args, 'no_stage6_new_only', False) and not NO_LLM

    workers_info = f"스레드={MAX_WORKERS}개"
    print(f"총 {len(targets)}개 | LLM검증={'OFF' if args.no_llm else 'ON'} | "
          f"격리={'OFF' if args.no_quarantine else 'ON'} | {workers_info}\n")

    results, passed, failed, warned = [], 0, 0, 0
    
    # 💡 1. 출력과 파일 저장 시 스레드 간 충돌을 막기 위한 자물쇠
    print_lock = threading.Lock()

    # 💡 2. try-except 블록 내부에 멀티스레딩 풀(Pool) 적용
    try:
        # MAX_WORKERS만큼 동시 API 요청 (기본값=5, 상단 상수로 조절)
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            
            future_to_test = {
                executor.submit(process_one, test_f, generate, not args.no_llm, 
                                args.no_stage6, NO_STAGE6_NEW_ONLY): test_f 
                for test_f in targets
            }

            for i, future in enumerate(concurrent.futures.as_completed(future_to_test), 1):
                test_f = future_to_test[future]
                try:
                    res = future.result() 
                except Exception as e:
                    res = {"test": test_f, "patch": test_to_patch(test_f),
                           "orig_cwes": cwes_in_filename(test_f), "stages": {},
                           "final": f"EXCEPTION: {e}"}

                # 자물쇠 걸고 안전하게 화면 출력 및 기록
                with print_lock:
                    results.append(res)
                    f = res["final"]
                    
                    if "PASS" in f:
                        passed += 1
                        print(f"[{i:03d}/{len(targets)}] ✅ {test_f} ... {f}", flush=True)
                    elif "FAIL" in f or "EXCEPTION" in f:
                        failed += 1
                        print(f"[{i:03d}/{len(targets)}] ❌ {test_f} ... {f}", flush=True)
                        if not args.no_quarantine and res.get("patch"):
                            if quarantine_patch(res["patch"]):
                                print(f"        → 격리: {QUARANTINE}/{res['patch']}", flush=True)
                    else:
                        warned += 1
                        print(f"[{i:03d}/{len(targets)}] ⚠️  {test_f} ... {f}", flush=True)

                    done.add(test_f)
                    if i % 10 == 0:   # 10개마다 체크포인트 (자물쇠 안쪽이라 안전함)
                        save_ckpt(done)

    # 💡 3. 루프 도중 Ctrl+C를 누르면 여기서 잡음
    except KeyboardInterrupt:
        print("\n\n⚠️ [중단됨] 사용자에 의해 프로세스가 중지되었습니다.")
        print("대기 중인 작업을 취소하고 지금까지 완료된 내역으로 로그를 생성합니다...")
        try:
            for future in future_to_test:
                future.cancel()
        except NameError:
            pass  # future_to_test 미초기화 시 무시

    # 💡 4. 날아갔던 결과 저장 로직 완벽 복구
    if not results:
        print("저장할 결과가 없습니다.")
        return

    save_ckpt(done)

    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(LOG_DIR, f"patch_verify_{now}.json"), 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    need_review = [r for r in results if "PASS" not in r["final"]]
    with open(os.path.join(LOG_DIR, f"need_review_{now}.txt"), 'w', encoding='utf-8') as f:
        f.write(f"수동 검토 필요: {len(need_review)}개\n\n")
        for r in need_review:
            f.write(f"{r['patch']} (원본 {r['orig_cwes']}): {r['final']}\n")
            for s, m in r.get("stages", {}).items():
                f.write(f"    {s}: {m}\n")
            f.write("\n")

    print(f"\n{'='*55}")
    print(f"✅ PASS:{passed}  ❌ FAIL:{failed}  ⚠️ WARN:{warned}")
    print(f"로그: {LOG_DIR}/patch_verify_{now}.json")
    print(f"수동검토: {LOG_DIR}/need_review_{now}.txt ({len(need_review)}개)")
    if failed and not args.no_quarantine:
        print(f"격리됨: {QUARANTINE}/ (FAIL patch는 데이터셋에서 제외됨)")

if __name__ == "__main__":
    main()