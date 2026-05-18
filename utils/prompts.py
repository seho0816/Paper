"""
utils/prompts.py
프롬프트 생성 함수.

[모델별 전략]
  Gemini / Qwen  → 한국어 (build_rag / build_raw / build_patch)
  Llama 3.2      → 영어   (build_rag_en / build_raw_en / build_patch_en)
                   소형 로컬 모델은 긴 한국어 지시에서 <CWE> 태그 미준수 현상 발생.
                   영어 + 짧은 구조로 태그 준수율 대폭 향상.

[환각 방지 - analyzer_gemini.py 반영]
  allowed_cwes : rag_engine.get_context() 의 3번째 반환값.
                 DB 검색 결과에서 수집된 CWE 번호만 최종 답으로 허용.
                 → DB 범위 밖 CWE를 모델이 임의로 확정하는 것을 차단.
"""

# ══════════════════════════════════════════════════════════════
# 공통 블록 — 한국어
# ══════════════════════════════════════════════════════════════

# (analyzer_gemini.py)의 CWE 분류 우선순위 규칙 전체 반영
_CWE_KO = """
[CWE 분류 우선순위 규칙]
1. 참고 지식에 여러 CWE가 포함된 경우 사용자 코드와 가장 직접적으로 일치하는 CWE를 우선 후보로 삼으세요.
2. 부모-자식 관계가 있는 후보 CWE 사이에서 하위 CWE를 무조건 우선하지 마세요.
   하위 CWE를 선택하려면 취약한 동작·원인·공격 시나리오가 해당 하위 CWE의 정의와 명확히 맞아야 합니다.
3. 최종 CWE는 "어떻게 고쳤는가"가 아니라 "어떤 취약 원인이 실제로 발생했는가"를 기준으로 선택하세요.
4. 여러 독립 취약점이 존재하면 하나로 합치지 말고 각각의 최종 CWE를 분리해서 작성하세요.
5. 참고 지식과 부분적으로만 일치하는 경우 확실한 취약점만 보고하고, 근거가 부족한 CWE는 "가능성 있음" 수준으로만 언급하세요.
""".strip()

_OUT_KO = """
=========================================
[출력 템플릿] — 이 양식을 그대로 따르세요

▶ 취약점 분석 및 원리:
(코드의 문제점과 패치 원리를 한국어로 설명)

▶ 맞춤형 개선 코드:
```python
(기존 코드를 안전하게 수정한 전체 코드)
```

▶ 최종 판단:
- 최종 CWE:
- 관련/상위 CWE:
- 최종 CWE로 판단한 이유:

[자동 채점 규칙 — 필수]
답변 맨 마지막에 반드시 <CWE>CWE-XXX</CWE> 형태로 단 하나만 출력하세요.
취약점이 없다면 <CWE>None</CWE>을 출력하세요.
""".strip()

_PATCH_OUT_KO = """
=========================================
[출력 템플릿] — 이 양식을 그대로 따르세요

▶ 코드 보안 검토:
(코드의 보안 상태를 한국어로 설명)

▶ 최종 판단:
(취약점이 있으면 CWE 번호, 없으면 None)

[자동 채점 규칙 — 필수]
답변 맨 마지막에 반드시 <CWE>CWE-XXX</CWE> 또는 <CWE>None</CWE>을 단 하나만 출력하세요.
안전한 코드라면 반드시 <CWE>None</CWE>을 출력하세요.
""".strip()


# ══════════════════════════════════════════════════════════════
# 공통 블록 — 영어 (Llama 3.2 전용, 간결하게 유지)
# ══════════════════════════════════════════════════════════════

_CWE_EN = """
[CWE Rules]
1. Prioritize the CWE most directly matching the code pattern.
2. Do not auto-prefer child CWEs; only use them when the root cause clearly fits.
3. Base the final CWE on what went wrong, not how it was fixed.
4. List each independent vulnerability separately.
""".strip()

_OUT_EN = """
=========================================
[Output — follow exactly]

▶ Analysis: (explain the vulnerability)
▶ Patched Code:
```python
(full patched code)
```
▶ Final decision: (CWE or None)

[MANDATORY] Last line of response: <CWE>CWE-XXX</CWE> or <CWE>None</CWE>
""".strip()

_PATCH_OUT_EN = """
=========================================
[Output — follow exactly]

▶ Review: (security status of this code)
▶ Final decision: (CWE if vulnerable, None if safe)

[MANDATORY] Last line: <CWE>CWE-XXX</CWE> or <CWE>None</CWE>
If the code is already secure: <CWE>None</CWE>
""".strip()


# ══════════════════════════════════════════════════════════════
# 내부 헬퍼 — DB 근거 제한 블록
# ══════════════════════════════════════════════════════════════

def _db_limit_ko(allowed_cwes: str) -> str:
    """allowed_cwes가 있을 때만 DB 범위 제한 블록을 생성한다."""
    if not allowed_cwes or allowed_cwes == "없음":
        return ""
    return f"""
[DB 근거 제한 규칙]
1. 최종 CWE는 반드시 아래 [허용 CWE 범위]에 포함된 것만 확정할 수 있습니다.
2. 목록 밖 CWE를 최종 취약점으로 선언하지 마세요.
3. 상위/관련 CWE는 보조 설명으로만 언급하세요.
4. DB 지식으로 직접 설명할 수 없는 문제는 최종 취약점으로 확정하지 마세요.

[허용 CWE 범위]
{allowed_cwes}
""".strip()


def _db_limit_en(allowed_cwes: str) -> str:
    if not allowed_cwes or allowed_cwes == "없음":
        return ""
    return f"""
[DB Scope]
Only confirm a final CWE from: {allowed_cwes}
Do not assert any CWE outside this list as a final finding.
""".strip()


# ══════════════════════════════════════════════════════════════
# 한국어 프롬프트 (Gemini / Qwen)
# ══════════════════════════════════════════════════════════════

def build_rag(code: str, rag_ctx: str, mitre_ctx: str,
              allowed_cwes: str = "") -> str:
    """RAG 있음, 한국어."""
    db_block = _db_limit_ko(allowed_cwes)
    return f"""당신은 파이썬 보안 전문가입니다.
아래 [참고 지식]을 바탕으로 [분석 대상 코드]의 취약점을 분석하세요.

[지시사항]
1. DB 예제 코드를 그대로 복사하지 마세요. 사용자 코드 맥락에 맞게 패치하세요.
2. 참고 지식과 관련 없으면 취약점 없음으로 판단하세요.
3. 가장 직접적인 원인 하나를 최종 CWE로 선택하세요.
4. 아래 출력 템플릿을 반드시 그대로 따르세요.

{_CWE_KO}

[MITRE 공식 기준]
{mitre_ctx}

[Security Knowledge Base]
{rag_ctx}

{db_block}

[분석 대상 코드]
{code}

{_OUT_KO}"""


def build_raw(code: str) -> str:
    """RAG 없음, 한국어."""
    return f"""당신은 파이썬 보안 전문가입니다.
아래 [분석 대상 코드]의 취약점을 자체 지식만으로 분석하세요.

[지시사항]
1. 취약점이 없으면 없음으로 판단하세요.
2. 가장 직접적인 원인 하나를 최종 CWE로 선택하세요.
3. 아래 출력 템플릿을 반드시 그대로 따르세요.

{_CWE_KO}

[분석 대상 코드]
{code}

{_OUT_KO}"""


def build_patch(code: str, rag_ctx: str = "", mitre_ctx: str = "") -> str:
    """패치 파일 전용, 한국어."""
    knowledge = ""
    if rag_ctx:
        knowledge = f"""
[참고 지식 — 취약/안전 패턴 비교용]
코드가 이미 안전한 패턴을 따른다면 취약점 없음으로 판단하세요.

[MITRE 공식 기준]
{mitre_ctx}

[Security Knowledge Base]
{rag_ctx}
""".strip()

    return f"""당신은 파이썬 보안 코드 검토 전문가입니다.
아래 [검토 대상 코드]의 보안 상태를 분석하세요.

[지시사항]
1. 이 코드는 이미 보안 패치가 적용된 코드일 수 있습니다.
2. 실제 취약점이 있는지 면밀히 검토하고 안전하다면 반드시 None으로 판단하세요.
3. 억지로 취약점을 찾지 마세요. 안전한 코드를 취약하다고 오진하는 것은 오탐(FP)입니다.
4. 아래 출력 템플릿을 반드시 그대로 따르세요.

{knowledge}

[검토 대상 코드]
{code}

{_PATCH_OUT_KO}"""


# ══════════════════════════════════════════════════════════════
# 영어 프롬프트 (Llama 3.2 전용)
# ══════════════════════════════════════════════════════════════

def build_rag_en(code: str, rag_ctx: str, mitre_ctx: str,
                 allowed_cwes: str = "") -> str:
    """RAG 있음, 영어."""
    db_block = _db_limit_en(allowed_cwes)
    return f"""You are a Python security expert.
Analyze the [Code] for vulnerabilities using the [Knowledge].

[Instructions]
1. Do not copy-paste KB examples. Patch the actual code.
2. If knowledge is unrelated, report no vulnerability.
3. Pick the single most direct root cause as the final CWE.
4. Follow the output template exactly. <CWE> tag is mandatory.

{_CWE_EN}

[MITRE Reference]
{mitre_ctx}

[Security Knowledge Base]
{rag_ctx}

{db_block}

[Code]
{code}

{_OUT_EN}"""


def build_raw_en(code: str) -> str:
    """RAG 없음, 영어."""
    return f"""You are a Python security expert.
Analyze the [Code] for vulnerabilities using only your knowledge.

[Instructions]
1. If no vulnerability exists, report none.
2. Pick the single most direct root cause as the final CWE.
3. Follow the output template exactly. <CWE> tag is mandatory.

{_CWE_EN}

[Code]
{code}

{_OUT_EN}"""


def build_patch_en(code: str, rag_ctx: str = "", mitre_ctx: str = "") -> str:
    """패치 파일 전용, 영어."""
    knowledge = ""
    if rag_ctx:
        knowledge = f"""
[Knowledge — compare vulnerable vs secure patterns]
If the code already follows secure patterns, report no vulnerability.

[MITRE Reference]
{mitre_ctx}

[Security Knowledge Base]
{rag_ctx}
""".strip()

    return f"""You are a Python security reviewer.
Check the security status of the [Code] below.

[Instructions]
1. This code may already be patched.
2. If it is secure, you MUST output <CWE>None</CWE>.
3. Do not force a finding. False positives on patched code are wrong.
4. Follow the output template exactly. <CWE> tag is mandatory.

{knowledge}

[Code]
{code}

{_PATCH_OUT_EN}"""
