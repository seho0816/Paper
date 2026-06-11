"""
utils/prompts.py
프롬프트 생성 함수.

[모델별 전략]
  Gemini / Claude / Grok → 한국어 (build_rag / build_raw / build_patch)
  Qwen / Llama           → 영어   (build_rag_en / build_raw_en / build_patch_en)

[analyzer_gemini_rag.py 기반 업데이트 - 2026.06]
  - CWE 분류 우선순위 규칙 10개 조항 완전 반영
  - DB 근거 제한 규칙 5개 조항 완전 반영
  - CWE-639 판정 조건 명시 (외부 입력 흐름 확인 필수)
  - Hallucination 방지 규칙 강화
"""

# ══════════════════════════════════════════════════════════════
# 한국어 공통 블록
# ══════════════════════════════════════════════════════════════

_HALLUCINATION_KO = """
[Hallucination 방지]
1. 제공된 [참고 지식(DB)]들을 복합적으로 참조하여 분석하세요.
2. [참고 지식(DB)]이 비어있거나 무관하다면 "저장된 지식 범위 내에서 확정 가능한 취약점을 찾지 못했습니다."라고만 답변하세요.
3. 취약점이 발견되더라도, DB에 있는 해결책 예제 코드를 그대로 복사하지 마세요.
4. 반드시 [분석 대상 코드]의 문맥을 유지하면서, 취약점만 안전하게 패치한 맞춤형 개선 코드를 작성하세요.

[지식 사용 규칙]
1. Python 취약/개선 예시 DB는 코드 패턴 탐지와 맞춤형 개선 코드 작성에 사용하세요.
2. 참고 지식과 부분적으로만 일치하는 경우 확실한 취약점만 보고하세요.
3. 근거가 부족한 CWE는 최종 CWE로 단정하지 말고 "가능성 있음", "관련 후보" 수준으로만 언급하세요.
""".strip()

_CWE_KO = """
[CWE 분류 우선순위 규칙]
1. 참고 지식에 여러 CWE가 포함된 경우 사용자 코드와 가장 직접적으로 일치하는 CWE를 우선 후보로 삼으세요.
2. 부모-자식 관계가 있는 후보 CWE 사이에서 하위 CWE를 무조건 우선하지 마세요.
   하위 CWE를 선택하려면 취약한 동작·원인·공격 시나리오가 해당 하위 CWE의 정의와 명확히 맞아야 합니다.
3. 코드가 상위 CWE 레슨/패턴과 더 직접적으로 일치한다면 상위 CWE를 최종 CWE로 선택할 수 있습니다.
4. 최종 CWE는 "어떻게 고쳤는가"가 아니라 "어떤 취약 원인이 실제로 발생했는가"를 기준으로 선택하세요.
5. 여러 독립 취약점이 존재하면 하나로 합치지 말고 각각의 최종 CWE를 분리해서 작성하세요.
6. 참고 지식과 부분적으로만 일치하는 경우 확실한 취약점만 보고하고, 근거 부족한 CWE는 "가능성 있음" 수준으로만 언급하세요.
7. 함수명·변수명·필드명만 보고 공격자 조작 가능성이나 외부 입력 여부를 추정하지 마세요. 코드에 명시된 사실만 근거로 삼으세요.
8. CWE-639를 최종 CWE로 판정하려면:
   - 객체 식별자가 외부 사용자 입력(request.args, request.json, URL 파라미터 등)에서 유입되고,
   - 소유권·권한 검증 없이 객체를 조회·수정·삭제하는 흐름이 코드에서 명확히 확인되어야 합니다.
   - 단순히 매개변수 이름이 user_id, order_id라는 이유만으로 단정하지 마세요.
9. 최종 출력에는 반드시 최종 CWE, 관련/상위 CWE, 최종 CWE로 판단한 이유를 분리해서 작성하세요.
10. 보안 개선 방법이 특정 통제를 포함한다는 이유만으로 최종 CWE를 변경하지 마세요.


[환각 방지 규칙 — 반드시 준수]
6. 코드에 명시적으로 드러난 사실만 근거로 판단하세요.
   다음은 코드에서 확인되지 않는 한 추정하지 마세요:
   - 웹훅 또는 외부 콜백 환경
   - 멀티테넌트 환경
   - 동시 요청 상황
   - 인증 사용자 컨텍스트
   - 추상화된 함수(complete, refund, approve)의 비멱등 부작용
   - repository 메서드 내부의 SQL 구현
7. 함수명·변수명만으로 내부 동작을 추정하지 마세요.
   refund, approve라는 이름이 실제 결제·환불 로직을 확정하지 않습니다.
8. '웹훅이라면', '재시도된다면', '외부 서비스를 호출할 수 있다면' 같은
   가정이 필요하면 None을 반환하세요.
9. 보안 통제 부재만으로는 충분하지 않습니다.
   위험 동작 자체가 코드에 명시적으로 존재해야 합니다.
""".strip()

_OUT_KO = """
=========================================
[출력 형식] — 반드시 따르세요 (간결하게 작성)

▶ 분석: (2~3줄 이내로 핵심만)
▶ 최종 CWE:
▶ 판단 이유: (1~2줄)

[필수 — 답변 맨 마지막 줄]
<CWE>CWE-XXX</CWE> 또는 취약점 없으면 <CWE>None</CWE>

주의: 코드 재작성 불필요. 분석은 짧게. 마지막 줄 태그가 채점에 사용됩니다.
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
# 영어 공통 블록 (Qwen / Llama 로컬 모델용)
# ══════════════════════════════════════════════════════════════

_CWE_EN = """
[CWE Rules]
1. Prioritize the CWE most directly matching the code pattern.
2. Do not auto-prefer child CWEs; only select them when the root cause clearly fits.
3. Base the final CWE on what went wrong, not how it was fixed.
4. Only report a CWE when the vulnerable pattern is explicitly visible in the code.
5. Do not infer attacker control from variable names alone; verify from actual code flow.

[Anti-Hallucination Rules — strictly follow]
6. Base your judgment ONLY on facts explicitly observable in the code.
   Do NOT assume or infer any of the following unless confirmed in the code:
   - That this runs as a webhook or external callback
   - That the environment is multi-tenant
   - That requests arrive concurrently
   - That an authenticated user context exists
   - That an abstracted function (complete, refund, approve, charge) has non-idempotent side effects
   - That a repository method executes a specific SQL query internally
7. Do not use function or variable names alone as evidence.
   A function named 'refund' or 'approve' does NOT confirm that actual payment/refund logic executes.
   Require the actual implementation or explicit API calls to be visible in the code.
8. If explaining why a vulnerability exists requires phrases like
   'if this were a webhook', 'could be multi-tenant', 'might retry',
   'possibly calls external service' — that is NOT a valid match. Report None.
9. Absence of a security control (e.g., no idempotency key, no auth check) alone
   is NOT sufficient. The risky operation itself must be explicitly present in the code.
""".strip()

_OUT_EN = """
=========================================
[Output — follow exactly]

▶ Vulnerability: (one sentence, the root cause)
▶ Final CWE: (CWE number or None)

[MANDATORY] Output exactly this on the last line: <CWE>CWE-XXX</CWE> or <CWE>None</CWE>
""".strip()

_PATCH_OUT_EN = """
=========================================
[Output — follow exactly]

▶ Status: (safe or vulnerable, one sentence)
▶ Final: (CWE if vulnerable, None if safe)

[MANDATORY] Last line: <CWE>CWE-XXX</CWE> or <CWE>None</CWE>
Safe code → <CWE>None</CWE>
""".strip()


# ══════════════════════════════════════════════════════════════
# 내부 헬퍼 — DB 근거 제한 블록 (analyzer_gemini_rag.py 5개 조항 완전 반영)
# ══════════════════════════════════════════════════════════════

def _db_limit_ko(allowed_cwes: str) -> str:
    if not allowed_cwes or allowed_cwes == "없음":
        return ""
    return f"""
[이번 분석에서 사용 가능한 CWE 범위]
{allowed_cwes}

[DB 근거 제한 규칙]
1. 최종 CWE로 확정할 수 있는 CWE는 반드시 위 [사용 가능한 CWE 범위]에 포함된 것만 허용됩니다.
2. 위 목록에 없는 CWE를 최종 취약점으로 확정하거나 직접 근거로 개선 코드를 생성하지 마세요.
3. 상위/관련/하위 후보 CWE는 보조 설명 수준에서만 언급하세요. 반드시 "관련 CWE", "상위 CWE", "후보 CWE"임을 명시하세요.
4. 제공된 참고 지식으로 직접 설명할 수 없는 문제는 최종 취약점으로 확정하지 마세요.
5. 검색된 DB 지식과 사용자 코드의 취약 원인이 직접 대응하지 않는다면 반드시 아래 문장만 출력하세요.
   "저장된 지식 범위 내에서 확정 가능한 취약점을 찾지 못했습니다."
""".strip()


def _db_limit_en(allowed_cwes: str) -> str:
    if not allowed_cwes or allowed_cwes == "없음":
        return ""
    return f"""
[Allowed CWE Scope]
{allowed_cwes}

[DB Scope Rules]
1. Only confirm a final CWE from the allowed scope above.
2. Do not assert any CWE outside this list as a final finding.
3. If knowledge does not directly match the code, output only: "No confirmable vulnerability found within stored knowledge."
""".strip()


# ══════════════════════════════════════════════════════════════
# 한국어 프롬프트 (Gemini / Claude / Grok)
# ══════════════════════════════════════════════════════════════

def build_rag(code: str, rag_ctx: str, mitre_ctx: str,
              allowed_cwes: str = "") -> str:
    """RAG 있음, 한국어."""
    db_block = _db_limit_ko(allowed_cwes)
    return f"""당신은 파이썬 보안 전문가입니다.
사용자가 입력한 코드 전체를 분석하세요.

{_HALLUCINATION_KO}

{_CWE_KO}

[MITRE 공식 기준]
{mitre_ctx}

[참고 지식(Security Knowledge Base)]
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
# 영어 프롬프트 (Qwen / Llama 로컬 모델용)
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