import os
import json
import re
import datetime
import chromadb
from google import genai
from google.genai import types
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
from dotenv import load_dotenv
from collections import defaultdict
from typing import Any

# --- 1. API 및 DB 셋업 ---
load_dotenv()
api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("⚠️ 오류: .env 파일에 'GEMINI_API_KEY'가 없습니다!")
    exit()
genai_client = genai.Client(api_key=api_key)


current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir) 

db_path = os.path.join(parent_dir, "rag_db")

try:
    db_clint = chromadb.PersistentClient(path=db_path)
    collection = db_clint.get_collection(name="python_security_lessons")
except Exception as e:
    print(f"DB 연결 실패: {e}")
    exit()

# --- 1-1. MITRE CWE 공식 JSON 로드 ---
mitre_json_path = os.path.join(parent_dir, "knowledge", "mitre_cwe_official.json")

try:
    with open(mitre_json_path, "r", encoding="utf-8-sig") as f:
        mitre_cwe_db = json.load(f)

    print(f"✅ MITRE CWE JSON 로드 완료: {mitre_json_path}")
    print("MITRE JSON key 목록:", list(mitre_cwe_db.keys()))

except FileNotFoundError:
    print(f"⚠️ MITRE CWE JSON 파일을 찾을 수 없습니다: {mitre_json_path}")
    mitre_cwe_db = {}
except json.JSONDecodeError as e:
    print(f"⚠️ MITRE CWE JSON 형식 오류: {e}")
    mitre_cwe_db = {}
except Exception as e:
    print(f"⚠️ MITRE CWE JSON 로드 실패: {e}")
    mitre_cwe_db = {}

RETRIEVAL_TOP_K = 20
MAX_DOCUMENTS_PER_CWE = 2
SHOW_RAW_RETRIEVAL = True
RAW_PREVIEW_PER_CHUNK = 3

def select_retrieved_evidence(
    retrieved_items: list[dict[str, Any]],
    max_documents_per_cwe: int = MAX_DOCUMENTS_PER_CWE,
) -> list[dict[str, Any]]:
    """
    여러 청크에서 검색된 결과를 정리한다.

    1. 동일 DB 문서는 가장 가까운 거리를 유지
    2. 검색된 청크 번호는 모두 보존
    3. CWE별 거리순 최대 N개 선택
    4. 직접 대응 검증기가 사용하는 evidence 형식으로 변환
    """

    # 동일 DB 문서를 하나로 합침
    merged_by_document_id: dict[str, dict[str, Any]] = {}

    for item in retrieved_items:
        document_id = item["id"]
        metadata = item.get("metadata") or {}
        distance = float(item["distance"])
        chunk_number = int(item["chunk_index"]) + 1

        found_cwes = extract_cwes_from_metadata_value(
            metadata.get("cwe")
        )

        if not found_cwes:
            continue

        # 직접 대응 검증에는 full_text가 필요함
        full_text = metadata.get("full_text") or item.get("document", "")

        current = merged_by_document_id.get(document_id)

        if current is None:
            merged_by_document_id[document_id] = {
                "source_id": document_id,
                "doc": full_text,
                "cwes": set(found_cwes),
                "best_distance": distance,
                "chunks": {chunk_number},
            }
        else:
            current["cwes"].update(found_cwes)
            current["chunks"].add(chunk_number)

            if distance < current["best_distance"]:
                current["best_distance"] = distance

                # 더 가까운 결과의 full_text가 있다면 보존
                if full_text:
                    current["doc"] = full_text

    # CWE별 그룹화
    grouped_by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for evidence in merged_by_document_id.values():
        for cwe in evidence["cwes"]:
            grouped_by_cwe[cwe].append(evidence)

    # CWE별 상위 N개 선택
    selected_by_source_id: dict[str, dict[str, Any]] = {}

    for cwe, items in grouped_by_cwe.items():
        items.sort(
            key=lambda evidence: evidence["best_distance"]
        )

        for evidence in items[:max_documents_per_cwe]:
            source_id = evidence["source_id"]

            if source_id not in selected_by_source_id:
                selected_by_source_id[source_id] = evidence

    # 전체 거리순 정렬
    selected = sorted(
        selected_by_source_id.values(),
        key=lambda evidence: evidence["best_distance"],
    )

    # Gemini 검증용 E1, E2 형식으로 변환
    evidence_items: list[dict[str, Any]] = []

    for index, evidence in enumerate(selected, start=1):
        pattern_name = extract_section_text(
            evidence["doc"],
            "취약점 명칭",
        )

        evidence_items.append({
            "id": f"E{index}",
            "source_id": evidence["source_id"],
            "doc": evidence["doc"],
            "cwes": sorted(evidence["cwes"]),
            "pattern_name": pattern_name or evidence["source_id"],
            "best_distance": evidence["best_distance"],
            "chunks": sorted(evidence["chunks"]),
        })

    return evidence_items

# --- 2. 🌳 트리시터 셋업 ---
PY_LANGUAGE = Language(tspython.language())
parser = Parser()
parser.language = PY_LANGUAGE

def node_text(node, source_bytes):
    """Tree-sitter node의 byte offset을 기준으로 안전하게 코드 문자열을 추출합니다."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")


def is_main_guard(node, source_bytes):
    """if __name__ == '__main__' 블록인지 간단히 판별합니다."""
    text = node_text(node, source_bytes)
    return node.type == "if_statement" and "__name__" in text and "__main__" in text


def extract_module_context(root_node, source_bytes):
    """
    함수/클래스 밖의 전역 설정 코드를 별도 청크로 추출합니다.
    예:
    - import 구문
    - app = Flask(__name__)
    - app.config["SECRET_KEY"] = ...
    - ADMIN_API_TOKEN = ...
    - CORS(...)
    - os.makedirs(...)
    """

    module_parts = []

    for child in root_node.children:
        # 함수/클래스/데코레이터 함수는 별도 청크에서 처리하므로 제외
        if child.type in ["function_definition", "class_definition", "decorated_definition"]:
            continue

        # if __name__ == "__main__"은 별도 청크에서 처리하므로 module context에서는 제외
        if child.type == "if_statement" and is_main_guard(child, source_bytes):
            continue

        # 전역 설정으로 의미 있는 노드만 수집
        if child.type in [
            "import_statement",
            "import_from_statement",
            "assignment",
            "expression_statement",
            "augmented_assignment",
            "comment",
        ]:
            text = node_text(child, source_bytes).strip()
            if text:
                module_parts.append(text)

    if not module_parts:
        return None

    return "# [MODULE_CONTEXT]\n" + "\n\n".join(module_parts)


def extract_all_functions(node, source_bytes, chunks_list):
    """
    함수, 클래스, 데코레이터가 포함된 함수, 최상단 main guard를 청크로 추출합니다.
    """

    # @app.route(...) 같은 데코레이터까지 포함해서 함수 청크 추출
    if node.type == "decorated_definition":
        chunk_code = node_text(node, source_bytes)
        chunks_list.append(chunk_code)
        return

    # 일반 함수/클래스 추출
    if node.type in ["function_definition", "class_definition"]:
        chunk_code = node_text(node, source_bytes)
        chunks_list.append(chunk_code)
        return

    # if __name__ == "__main__": 블록 추출
    elif node.type == "if_statement":
        if node.parent and node.parent.type == "module":
            if is_main_guard(node, source_bytes):
                chunk_code = node_text(node, source_bytes)
                chunks_list.append(chunk_code)
                return

    # 자식 노드 탐색
    for child in node.children:
        extract_all_functions(child, source_bytes, chunks_list)

def extract_cwes_from_metadata_value(cwe_value):
    """
    metadata의 cwe 값에서 CWE 번호를 추출합니다.
    예:
    'CWE-942'
    'CWE-117, CWE-532'
    """
    if not cwe_value:
        return []

    return re.findall(r"CWE-\d+", str(cwe_value))

def build_mitre_context(candidate_cwes, mitre_cwe_db):
    """
    최종 판정된 CWE ID 목록을 기준으로
    MITRE JSON 공식 지식을 exact lookup하여 출력용 문자열로 구성합니다.
    """
    sections = []

    for cwe in sorted(candidate_cwes):
        info = mitre_cwe_db.get(cwe)
        if not info:
            continue

        parent_cwe = ", ".join(info.get("parent_cwe", [])) or "없음"
        related_cwe = ", ".join(info.get("related_cwe", [])) or "없음"

        sections.append(f"""
--- [MITRE 공식 기준: {cwe}] ---
공식명: {info.get("official_title", "")}
추상화 수준: {info.get("abstraction", "")}
취약점 매핑: {info.get("vulnerability_mapping", "")}
공식 요약: {info.get("summary_ko", "")}
공식 완화 방향: {info.get("mitigation_ko", "")}
상위 CWE: {parent_cwe}
관련 CWE: {related_cwe}
Python 관련 메모: {info.get("python_note", "")}
출처: {info.get("source_url", "")}
""".strip())

    if not sections:
          return "최종 CWE에 해당하는 MITRE 공식 기준 정보가 현재 JSON에 등록되어 있지 않습니다."

    return "\n\n".join(sections)

def extract_final_cwes_from_result(result_text):
    """
    Gemini 분석 결과에서 최종 CWE를 추출합니다.
    우선 <CWE>...</CWE> 태그를 사용하고,
    태그가 없으면 '최종 CWE' 항목을 보조적으로 탐색합니다.
    """
    tagged_cwes = re.findall(r"<CWE>\s*(CWE-\d+)\s*</CWE>", result_text)
    if tagged_cwes:
        return list(dict.fromkeys(tagged_cwes))

    final_cwes = []
    lines = result_text.splitlines()

    for idx, line in enumerate(lines):
        cleaned_line = (
            line.replace("*", "")
                .replace("#", "")
                .replace("`", "")
                .strip()
        )

        # 예:
        # "2. 최종 CWE"
        # "최종 CWE"
        # "최종 CWE: CWE-287"
        match = re.match(
            r"^(?:\d+\.\s*)?최종 CWE(?:\s*:?\s*(.*))?$",
            cleaned_line
        )

        if not match:
            continue

        # 같은 줄에 CWE가 있는 경우
        same_line_tail = match.group(1) or ""
        cwes = re.findall(r"CWE-\d+", same_line_tail)

        # 같은 줄에 없으면 다음 1~2줄에서 찾기
        if not cwes:
            for next_line in lines[idx + 1: idx + 3]:
                next_cwes = re.findall(r"CWE-\d+", next_line)
                if next_cwes:
                    cwes.extend(next_cwes)
                    break

        for cwe in cwes:
            if cwe not in final_cwes:
                final_cwes.append(cwe)

    return final_cwes

def parse_json_object_from_text(text):
    """
    Gemini가 반환한 JSON 문자열을 안전하게 파싱합니다.
    ```json ... ``` 코드펜스가 있어도 처리합니다.
    """
    cleaned = text.strip()

    cleaned = re.sub(r"^```json\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^```\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        raise ValueError("응답에서 JSON 객체를 찾지 못했습니다.")

    return json.loads(match.group(0))

def extract_section_text(full_text, section_name):
    """
    full_text에서 [취약점 명칭] 같은 섹션 값을 추출합니다.
    """
    pattern = rf"\[{re.escape(section_name)}\]\s*(.*?)(?=\n\[[^\]]+\]|\Z)"
    match = re.search(pattern, full_text, re.DOTALL)

    if not match:
        return ""

    return match.group(1).strip()


def build_evidence_lookup(evidence_items):
    """
    evidence_id 기준으로 evidence item을 찾기 쉽게 변환합니다.
    """
    return {
        item["id"]: item
        for item in evidence_items
    }


def group_matched_results_by_cwe(matched_results, evidence_items):
    """
    직접 대응 검증 결과를 CWE 기준으로 묶습니다.

    반환 예:
    {
        "CWE-327": {
            "count": 2,
            "items": [...]
        }
    }
    """
    evidence_by_id = build_evidence_lookup(evidence_items)
    grouped = {}

    for match in matched_results:
        evidence_id = match.get("evidence_id")
        evidence = evidence_by_id.get(evidence_id)

        if not evidence:
            continue

        pattern_name = extract_section_text(evidence["doc"], "취약점 명칭")
        if not pattern_name:
            pattern_name = evidence_id

        for cwe in match.get("matched_cwes", []):
            grouped.setdefault(cwe, [])

            grouped[cwe].append({
                "evidence_id": evidence_id,
                "cwe": cwe,
                "pattern_name": pattern_name,
                "reason": match.get("reason", ""),
                "best_distance": evidence.get("best_distance", 999),
                "chunks": evidence.get("chunks", []),
                "doc": evidence.get("doc", ""),
                "evidence": evidence,
            })

    # CWE별로 유사도 거리 낮은 순 정렬
    for cwe in grouped:
        grouped[cwe].sort(key=lambda x: x.get("best_distance", 999))

    return grouped


def print_grouped_matched_results(matched_results, evidence_items, show_detail=False):
    """
    기존 E1, E2, E3 나열 방식 대신 CWE 기준 요약 출력.
    show_detail=True면 각 evidence 상세도 같이 출력합니다.
    """
    grouped = group_matched_results_by_cwe(matched_results, evidence_items)

    if not grouped:
        print("직접 대응한다고 판정된 DB 지식이 없습니다.")
        print("================================================\n")
        return

    for cwe, items in grouped.items():
        representative = items[0]

        print(f"✅ {cwe} 직접 대응 확인")
        print(f"   - 매칭 근거 수: {len(items)}개")
        print(f"   - 대표 패턴: {representative['pattern_name']}")
        print(f"   - 대표 사유: {representative['reason']}")

        if len(items) > 1:
            print("   - 보조 패턴:")
            for item in items[1:]:
                print(
                    f"     · {item['pattern_name']} "
                    f"(근거 {item['evidence_id']}, 거리 {item['best_distance']:.4f})"
                )

        if show_detail:
            print("   - 상세 근거:")
            for item in items:
                print(
                    f"     · {item['evidence_id']} / "
                    f"{item['pattern_name']} / "
                    f"거리 {item['best_distance']:.4f} / "
                    f"청크 {item['chunks']}"
                )

        print()


def select_representative_verified_items(matched_results, evidence_items, max_per_cwe=2):
    """
    AI 분석 프롬프트에 넘길 DB 지식을 CWE별 대표 근거만 남깁니다.
    같은 CWE에서 너무 많은 DB 문서가 들어가 중복 분석되는 것을 방지합니다.
    """
    grouped = group_matched_results_by_cwe(matched_results, evidence_items)

    selected = []
    selected_ids = set()

    for cwe, items in grouped.items():
        for item in items[:max_per_cwe]:
            evidence = item["evidence"]
            evidence_id = evidence["id"]

            if evidence_id in selected_ids:
                continue

            selected.append(evidence)
            selected_ids.add(evidence_id)

    return selected

def verify_retrieved_evidences(genai_client, user_code, evidence_items):
    """
    RAG로 검색된 DB 지식이 사용자 코드의 취약 원인과
    직접적으로 대응하는지 검증합니다.

    반환:
    {
        "verified_items": [...],
        "verified_cwes": set(...),
        "matched_results": [...],
        "raw_response": "..."
    }
    """

    if not evidence_items:
        return {
            "verified_items": [],
            "verified_cwes": set(),
            "matched_results": [],
            "raw_response": ""
        }

    evidence_text = "\n\n".join(
        [
            f"""
--- [근거 문서 {item['id']}] ---
메타데이터 CWE: {", ".join(item['cwes'])}
DB 지식:
{item['doc']}
""".strip()
            for item in evidence_items
        ]
    )

    verification_prompt = f"""
당신은 'DB 근거 직접 대응 검증기'입니다.

목표:
사용자 코드의 취약 원인과 검색된 DB 지식의 '구체 취약 패턴'이
직접적으로 대응하는지 엄격하게 검증하세요.

중요 규칙:
1. CWE 번호가 같다는 이유만으로 MATCH 처리하지 마세요.
2. 같은 상위 보안 주제에 속하더라도, 실제 취약 원인과 공격 방식이 다르면 NO_MATCH입니다.
3. 변수명, 함수명, 라우트명, 도메인이 달라도 취약 원리가 같으면 MATCH 가능합니다.
4. 그러나 DB 지식은 토큰 위조인데 사용자 코드는 평문 파일 저장처럼,
   구체 패턴이 다르면 반드시 NO_MATCH입니다.
5. 외부 보안 지식으로 추론을 보강하지 마세요.
6. 오직 [DB 지식]과 [사용자 코드]의 직접 대응 여부만 판단하세요.
7. 확신이 부족하면 NO_MATCH로 처리하세요.
8. 코드에 명시적으로 드러난 사실만 근거로 판단하세요.
함수명, 변수명, 필드명만 보고 공격자 조작 가능성이나 외부 입력 여부를 추정하지 마세요.

단, 아래의 특정 CWE 전용 규칙에서 허용한 경우에는 이름만이 아니라
실제 함수 인자 전달, 필드 접근, 조건 분기, 위험 API 또는 민감 동작 호출이
함께 확인되는 전체 데이터 흐름을 근거로 판단할 수 있습니다
9. 단순히 필요한 보안 통제 코드가 보이지 않는다는 이유만으로 MATCH하지 마세요.

보안 통제의 부재를 핵심 조건으로 하는 CWE는 다음 조건이 함께 확인되어야 합니다.

사용자 코드에 해당 통제가 실제로 필요한 위험 동작이 존재함
통제 부재로 인해 DB 지식에 설명된 공격이나 잘못된 상태가 발생할 수 있는
구체적인 코드 흐름이 확인됨

10. CWE-502에 한해서는 다음 조건이 모두 확인될 경우,
request, UploadFile, HTTP body 같은 명시적 외부 입력 API가 보이지 않더라도
간접 데이터 흐름이 확인된 것으로 판단하여 MATCH할 수 있습니다.

사용자 코드에 pickle.loads, pickle.load, dill.loads, dill.load,
yaml.load, jsonpickle.decode 같은 위험한 역직렬화 API가 실제로 존재함
역직렬화 대상이 코드 내부의 고정 상수나 리터럴이 아님
함수 또는 메서드 인자로 전달된 동일 데이터가 호출 관계를 따라
위험한 역직렬화 API까지 전달되는 흐름이 사용자 코드 전체에서 확인됨
역직렬화 전에 서명, HMAC, 무결성 검증 또는 신뢰 출처 검증이 확인되지 않음
검색된 DB 문서 역시 동일한 위험 역직렬화 API를 다루는 CWE-502 문서임

함수명이나 변수명만으로 MATCH하지 마세요.
uploaded, payload, serialized 같은 이름은 실제 인자 전달 흐름이
함께 확인될 때만 보조 근거로 사용할 수 있습니다.

다음 경우에는 CWE-502로 MATCH하지 마세요.

코드 내부에 고정된 bytes 또는 테스트 fixture를 역직렬화함
서버 내부에서만 생성된 데이터라는 흐름이 명확함
역직렬화 전에 서명 또는 HMAC 검증이 수행됨
json.loads, yaml.safe_load처럼 임의 객체 실행이 불가능한 안전한 파서를 사용함

단순한 역직렬화 이후 타입 검사만으로는 pickle/dill의 코드 실행 위험이
제거되지 않으므로, 타입 검사만 있다는 이유로 NO_MATCH 처리하지 마세요.

     11. CWE-642를 MATCH로 판정할 때는 다음 조건이 모두 확인되어야 합니다.

payment_confirmed, payment_required, is_paid, approved,
verified, workflow_state 같은 보안상 중요한 상태값이 존재함
해당 상태값이 함수 또는 메서드 입력으로 전달된 dict/object에서 읽힘
그 상태값이 주문 완료, 결제 완료, 승인, 권한 부여 등
민감한 서버 상태 변경의 실행 여부를 직접 결정함
서버 DB, 결제 제공자, 검증된 세션 또는 신뢰할 수 있는
서버 측 저장소에서 실제 상태를 재조회하거나 검증하는 코드가 없음
검색된 DB 문서가 외부에서 제어 가능한 중요 상태값을 신뢰하는
CWE-642 문서임

request.json, request.form 같은 명시적인 웹 입력 API가 없더라도,
함수 인자로 받은 상태 객체의 중요 필드가 조건식에 사용되고
그 결과가 민감한 상태 변경 호출로 직접 이어지면 MATCH할 수 있습니다.

submitted_state, form_state, client_state 같은 이름만으로 MATCH하지 마세요.
다음 실제 흐름이 함께 확인되어야 합니다.

입력 상태 필드
→ 조건 판단
→ 민감한 서버 상태 변경 함수 호출

다음 경우에는 CWE-642로 MATCH하지 마세요.

입력 상태값을 서버 DB 또는 결제 제공자에게 다시 확인함
상태값이 화면 표시나 응답 구성에만 사용됨
입력값이 민감한 상태 변경이나 권한 판단에 영향을 주지 않음
서버가 생성하고 무결성을 보호한 상태 객체임이 명확함

    12. CWE-837을 MATCH로 판정할 때는 단순히 idempotency 관련 코드가
보이지 않는다는 이유만으로 MATCH하지 마세요.

다음 조건이 모두 확인되어야 합니다.

결제 승인, 결제 취소, 환불, 포인트 지급·차감,
쿠폰 발급·사용, 외부 메시지 발송, 중복 INSERT처럼
반복 실행 시 실제 부작용이 중복 발생하는 작업이 존재함
해당 작업이 외부 요청 처리 함수나 반복 호출 가능한 서비스 경로에 존재하여
같은 논리 작업이 다시 호출될 가능성이 있음
동일 order_id, payment_id, request_id 등에 대한 처리 완료 여부,
상태 잠금 또는 idempotency key 검사가 없음
검색된 DB 문서의 단일 고유 작업 보장 누락 패턴과 직접 일치함

다음 경우에는 CWE-837로 MATCH하지 마세요.

mark_order_completed, update_status, set_processed처럼
동일한 고정 상태를 설정하는 함수가 한 번 호출되는 것만 확인됨
호출되는 함수의 내부 구현이 없어 비멱등 부작용을 확정할 수 없음
동일한 논리 작업의 반복 호출 가능성이 코드 문맥에서 확인되지 않음
단순히 idempotency key가 보이지 않는다는 이유만으로 추론함

13. 특히 CWE-639를 MATCH로 판정하려면 다음 조건이 확인되어야 합니다.

객체 식별자(user_id, order_id, doc_id 등)가
외부 사용자가 조작할 수 있는 입력에서 유입되었거나,
코드 전체에서 외부 입력이 해당 식별자로 전달되는 흐름이 명시적으로 보여야 함
예: request.args, request.form, request.json, request.cookies,
request.headers, Flask URL path parameter 또는 이러한 값이 다른 함수 인자로 전달되는 경우
그 식별자를 기반으로 특정 객체를 조회, 수정, 삭제 또는 저장함
해당 객체에 대한 현재 사용자 소유권 또는 접근 권한 검증이 누락됨

14. 단순히 함수 매개변수 이름이 user_id, order_id, doc_id라는 이유만으로
    사용자 통제 식별자라고 단정하지 마세요.
    코드 전체에서 외부 입력 유입 또는 전달 흐름이 확인되지 않으면 NO_MATCH로 처리하세요.
    
각 근거 문서에 대해:
- 직접 대응하면 matches에 포함
- 직접 대응하지 않으면 rejected에 포함

matched_cwes에는 해당 근거 문서의 메타데이터 CWE 중
이번 사용자 코드에 직접 적용되는 CWE만 적으세요.

반드시 아래 JSON 형식으로만 답변하세요.
설명 문장, 마크다운, 코드블록은 출력하지 마세요.

{{
  "matches": [
    {{
      "evidence_id": "E1",
      "matched_cwes": ["CWE-639"],
      "reason": "사용자 통제 order_id로 객체를 선택하고 소유권 검증 없이 상태를 변경하는 구조가 DB 패턴과 직접 일치함"
    }}
  ],
  "rejected": [
    {{
      "evidence_id": "E2",
      "reason": "CWE 번호는 유사하지만 DB 지식의 구체 취약 패턴과 사용자 코드의 원인이 다름"
    }}
  ]
}}

[사용자 코드]
{user_code}

[검색된 DB 지식]
{evidence_text}
"""

    response = genai_client.models.generate_content(
        model='gemini-2.5-flash',
        contents=verification_prompt,
        config=types.GenerateContentConfig(
            temperature=0,
            seed=42,
            response_mime_type="application/json"
        )
    )

    raw_response = response.text or ""

    try:
        parsed = parse_json_object_from_text(raw_response)
    except Exception:
        # 검증 응답 파싱에 실패하면 보수적으로 모두 거부
        return {
            "verified_items": [],
            "verified_cwes": set(),
            "matched_results": [],
            "raw_response": raw_response
        }

    evidence_by_id = {item["id"]: item for item in evidence_items}

    verified_items = []
    verified_cwes = set()
    matched_results = []

    for match in parsed.get("matches", []):
        evidence_id = match.get("evidence_id")
        if evidence_id not in evidence_by_id:
            continue

        evidence = evidence_by_id[evidence_id]

        matched_cwes = set(match.get("matched_cwes", []))
        allowed_doc_cwes = set(evidence["cwes"])

        # 문서 메타데이터에 존재하는 CWE만 인정
        valid_matched_cwes = matched_cwes & allowed_doc_cwes

        if not valid_matched_cwes:
            continue

        verified_items.append(evidence)
        verified_cwes.update(valid_matched_cwes)

        matched_results.append({
            "evidence_id": evidence_id,
            "matched_cwes": sorted(valid_matched_cwes),
            "reason": match.get("reason", "")
        })

    return {
        "verified_items": verified_items,
        "verified_cwes": verified_cwes,
        "matched_results": matched_results,
        "raw_response": raw_response
    }

def parse_and_chunk(source_code):
    """
    코드를 파싱하여 보안 분석용 청크 리스트를 반환합니다.
    1. 전역 설정 청크
    2. 데코레이터 포함 함수/메서드 청크
    3. main guard 청크
    """
    source_bytes = source_code.encode("utf-8")
    tree = parser.parse(source_bytes)
    root_node = tree.root_node

    chunks = []

    # 1. 전역 설정 청크 먼저 추가
    module_context = extract_module_context(root_node, source_bytes)
    if module_context:
        chunks.append(module_context)

    # 2. 함수/클래스/main guard 청크 추가
    extract_all_functions(root_node, source_bytes, chunks)

    return chunks


NO_FINDING_MESSAGE = "저장된 지식 범위 내에서 확정 가능한 취약점을 찾지 못했습니다."
RESULT_DIR = "result"


def save_analysis_report(
    target_file: str,
    status: str,
    summary: str,
    *,
    failure_stage: str = "",
    result_text: str = "",
    final_cwes: list[str] | None = None,
    final_mitre_context: str = "",
    evidence_items: list[dict[str, Any]] | None = None,
    matched_results: list[dict[str, Any]] | None = None,
    verified_candidate_cwes: set[str] | list[str] | None = None,
    verification_raw_response: str = "",
    model_raw_response: str = "",
    error_message: str = "",
) -> str:
    """
    탐지 성공뿐 아니라 미탐지, 보류, 결과 차단, 실행 오류도 result 폴더에 저장합니다.

    상태 예:
    - DETECTED_AND_PATCHED
    - NO_CONFIRMED_VULNERABILITY
    - RESULT_REJECTED
    - ERROR
    """
    os.makedirs(RESULT_DIR, exist_ok=True)

    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(
        os.path.basename(target_file)
    )[0]
    filename = os.path.join(
        RESULT_DIR,
        f"result_gemini_{base_name}_{now}.txt",
    )

    evidence_items = evidence_items or []
    matched_results = matched_results or []
    final_cwes = final_cwes or []
    verified_candidate_cwes = sorted(
        set(verified_candidate_cwes or [])
    )

    with open(filename, "w", encoding="utf-8") as file:
        file.write(
            f"=== RAG + Gemini 보안 분석 리포트 ({now}) ===\n"
        )
        file.write(
            f"=== 분석 대상 파일: {target_file} ===\n\n"
        )
        file.write(f"분석 상태: {status}\n")
        file.write(f"결과 요약: {summary}\n")

        if failure_stage:
            file.write(f"종료 단계: {failure_stage}\n")

        file.write(
            "확정된 최종 CWE: "
            + (
                ", ".join(final_cwes)
                if final_cwes
                else "없음"
            )
            + "\n"
        )
        file.write(
            "직접 대응 검증을 통과한 CWE 후보: "
            + (
                ", ".join(verified_candidate_cwes)
                if verified_candidate_cwes
                else "없음"
            )
            + "\n"
        )
        file.write(
            f"검색 후 선별된 DB 근거 수: {len(evidence_items)}\n"
        )
        file.write(
            f"직접 대응 근거 수: {len(matched_results)}\n"
        )

        if error_message:
            file.write(f"오류 내용: {error_message}\n")

        file.write("\n=== 검색된 DB 근거 요약 ===\n")

        if evidence_items:
            for item in evidence_items:
                file.write(
                    "- "
                    f"{item.get('id', '')} / "
                    f"source_id={item.get('source_id', '')} / "
                    f"CWE={', '.join(item.get('cwes', [])) or 'UNKNOWN'} / "
                    f"거리={item.get('best_distance', 999):.4f} / "
                    f"청크={item.get('chunks', [])} / "
                    f"패턴={item.get('pattern_name', '')}\n"
                )
        else:
            file.write("없음\n")

        file.write("\n=== DB 근거 직접 대응 검증 결과 ===\n")

        if matched_results:
            for match in matched_results:
                file.write(
                    "- "
                    f"근거={match.get('evidence_id', '')} / "
                    f"CWE={', '.join(match.get('matched_cwes', []))} / "
                    f"사유={match.get('reason', '')}\n"
                )
        else:
            file.write("직접 대응한다고 판정된 DB 지식이 없습니다.\n")

        if verification_raw_response:
            file.write(
                "\n=== 직접 대응 검증기 원본 응답 ===\n"
            )
            file.write(verification_raw_response.strip())
            file.write("\n")

        if result_text:
            file.write("\n=== AI 분석 결과 ===\n")
            file.write(result_text.strip())
            file.write("\n")
        elif model_raw_response:
            file.write("\n=== AI 원본 응답 ===\n")
            file.write(model_raw_response.strip())
            file.write("\n")
        else:
            file.write("\n=== AI 분석 결과 ===\n")
            file.write(summary)
            file.write("\n")

        if final_mitre_context:
            file.write("\n=== MITRE 공식 기준 보강 ===\n")
            file.write(final_mitre_context.strip())
            file.write("\n")

    print(
        f"✅ 분석 결과가 '{filename}' 파일에 저장되었습니다! "
        f"(상태: {status})"
    )

    return filename


# --- 3. 메인 분석 루프 ---
print("=== RAG + Tree-sitter 파이썬 보안 분석 시스템 ===")
print("분석할 파일의 경로를 입력하세요. (예: bandit_test/CWE-338_CWE-343test.py)")
print("종료하려면 'exit'을 입력하세요.")

while True:
    print("\n[파일 경로 입력 대기 중...]")
    target_file = input("경로: ").strip()
    
    if target_file.lower() == 'exit':
        print("프로그램을 종료합니다.")
        break
        
    if not target_file:
        continue

    # 1. 파일 존재 여부 확인
    if not os.path.exists(target_file):
        print(f"⚠️ 오류: '{target_file}' 파일을 찾을 수 없습니다. 경로를 다시 확인해주세요.")
        continue

    # 2. 파일 읽어오기
    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            user_code = f.read()
    except Exception as e:
        print(f"⚠️ 파일 읽기 오류: {e}")
        continue

    if not user_code.strip():
        print("⚠️ 오류: 파일이 비어있습니다.")
        continue

    print(f"\n[1/3] ✂️ Tree-sitter로 '{target_file}' 코드 청킹(Chunking) 진행 중...")
    chunks = parse_and_chunk(user_code)
    
    # 함수가 없는 단순 스크립트라면 전체 코드를 하나의 청크로 사용
    if not chunks:
        chunks = [user_code]
        print(" -> 함수 구조가 없어 전체 코드를 단일 블록으로 분석합니다.")
    else:
        print(f" -> 총 {len(chunks)}개의 코드 청크를 식별하여 분리했습니다!\n")
        
        # ==========================================
        # 🛠️ [디버그] 추출된 청크(함수) 내용 출력 로직
        # ==========================================
        print("=== 🛠️ [디버그] Tree-sitter 파싱 결과 확인 ===")
        for i, chunk in enumerate(chunks):
            print(f"▶️ [청크 {i+1}]")
            chunk_lines = chunk.split('\n')
            for line in chunk_lines:
                print(f"  | {line}")
            print("-" * 50)
        print("==============================================\n")

        print("[2/3] 🔍 DB에서 각 함수별로 취약점 패턴 검색 중...")
    DISTANCE_THRESHOLD = 1.8

    db_size = collection.count()

    if db_size == 0:
        print("⚠️ DB가 비어있습니다. 데이터를 먼저 추가해주세요.")
        continue

    retrieval_k = min(RETRIEVAL_TOP_K, db_size)

    all_retrieved_items: list[dict] = []

    for chunk_index, chunk in enumerate(chunks):
        results = collection.query(
            query_texts=[chunk],
            n_results=retrieval_k,
            include=["documents", "metadatas", "distances"],
        )

        ids = results.get("ids", [[]])[0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        chunk_retrieved_items = []

        for document_id, document, metadata, distance in zip(
            ids,
            documents,
            metadatas,
            distances,
        ):
            metadata = metadata or {}
            distance = float(distance)

            if distance >= DISTANCE_THRESHOLD:
                continue

            item = {
                "id": document_id,
                "document": document or "",
                "metadata": metadata,
                "distance": distance,
                "chunk_index": chunk_index,
                "chunk": chunk,
            }

            all_retrieved_items.append(item)
            chunk_retrieved_items.append(item)

        # 디버깅이 필요할 때만 청크별 상위 일부 출력
        if SHOW_RAW_RETRIEVAL:
            print(
                f"  📍 [청크 {chunk_index + 1}] "
                f"검색 결과 {len(chunk_retrieved_items)}개"
            )

            for item in chunk_retrieved_items[:RAW_PREVIEW_PER_CHUNK]:
                print(
                    f"     - CWE={item['metadata'].get('cwe', 'UNKNOWN')} "
                    f"거리={item['distance']:.4f}"
                )

    # 동일 문서 제거 후 CWE별 최대 2개 선택
    evidence_items = select_retrieved_evidence(
        retrieved_items=all_retrieved_items,
        max_documents_per_cwe=MAX_DOCUMENTS_PER_CWE,
    )

    print("\n[3/4] 🧾 검색된 DB 지식과 사용자 코드의 직접 대응 여부를 검증합니다...")

    verification_result = verify_retrieved_evidences(
        genai_client,
        user_code,
        evidence_items
        )

    verified_items = verification_result["verified_items"]
    verified_candidate_cwes = verification_result["verified_cwes"]
    matched_results = verification_result["matched_results"]

    verified_items_for_prompt = select_representative_verified_items(
        matched_results,
        evidence_items,
        max_per_cwe=2
    )

    print("\n=== 🧾 [디버그] DB 근거 직접 대응 검증 결과 ===")
    print_grouped_matched_results(
        matched_results,
        evidence_items,
        show_detail=False
    )

    if not verified_items_for_prompt or not verified_candidate_cwes:
        print("\n================ [AI 분석 결과] ================")
        print(NO_FINDING_MESSAGE)
        print("================================================\n")

        save_analysis_report(
            target_file=target_file,
            status="NO_CONFIRMED_VULNERABILITY",
            summary=NO_FINDING_MESSAGE,
            failure_stage="direct_evidence_verification",
            evidence_items=evidence_items,
            matched_results=matched_results,
            verified_candidate_cwes=verified_candidate_cwes,
            verification_raw_response=verification_result.get(
                "raw_response",
                "",
            ),
        )
        continue

    print(
        f"\n[4/4] 🧠 {len(verified_items_for_prompt)}개의 대표 DB 지식을 바탕으로 "
        "AI 정밀 분석을 시작합니다..."
    )

    retrieved_context = "\n\n".join(
        [
            f"""--- [검증 통과 DB 지식 {idx+1}] ---
            패턴명: {item.get('pattern_name', '')}
            CWE: {", ".join(item.get('cwes', []))}
            최소 유사도 거리: {item.get('best_distance', 999):.4f}
            매칭 청크: {item.get('chunks', [])}

            {item['doc']}"""
                    for idx, item in enumerate(verified_items_for_prompt)
        ]
    )

    retrieved_candidate_cwes = set(verified_candidate_cwes)

    allowed_cwes_text = ", ".join(sorted(retrieved_candidate_cwes)) \
        if retrieved_candidate_cwes else "없음"

    prompt = f"""
        당신은 파이썬 보안 전문가입니다. 
        사용자가 입력한 코드 전체를 분석하세요.
        
        Hallucination 방지
        1. 제공된 [참고 지식(DB)]들을 복합적으로 참조하여 분석하세요.
        2. [참고 지식(DB)]이 비어있거나 무관하다면 "저장된 지식 범위 내에서 확정 가능한 취약점을 찾지 못했습니다." 라고만 답변하세요.
        3. 취약점이 발견되더라도, DB에 있는 해결책 예제 코드를 그대로 복사하지 마세요.
        4. 반드시 [사용자 입력 전체 코드]의 문맥을 유지하면서, 취약점만 안전하게 패치한 '사용자 맞춤형 개선 코드'를 작성하세요. 개선 코드는 함수명을 변경하지 마세요.
        5. 수정된 코드와 함께 관련 CWE 번호 및 패치 원리를 설명하세요.
        6. 사용자 입력 코드에서 취약점이 발견된 코드는 개별 항목을 만들어서 취약 코드를 똑같이 적어주세요.

        [지식 사용 규칙]
        1. Python 취약/개선 예시 DB는 Python 코드 패턴 탐지와 사용자 맞춤형 개선 코드 작성에 사용하세요.
        2. 참고 지식과 사용자 코드가 부분적으로만 일치하는 경우, 확실한 취약점만 보고하세요.
        3. 근거가 부족한 CWE는 최종 CWE로 단정하지 말고 "가능성 있음", "관련 후보" 수준으로만 언급하세요.

        [CWE 분류 우선순위 규칙]
        1. 참고 지식에 여러 CWE가 포함되어 있을 경우, 사용자 코드와 가장 직접적으로 일치하는 참고 지식의 CWE를 우선 후보로 삼으세요.

        2. 후보 CWE들 사이에 부모-자식 또는 상위-하위 관계가 있는 경우, 하위 CWE를 무조건 우선하지 마세요. 
        사용자 코드의 핵심 원인이 하위 CWE의 정의와 명확히 일치할 때만 하위 CWE를 최종 CWE로 선택하세요.

        3. 코드가 특정 참고 지식 또는 레슨 문서의 취약 코드 패턴과 매우 직접적으로 일치하고, 그 문서의 CWE가 상위 CWE라면 해당 상위 CWE를 최종 CWE로 유지할 수 있습니다. 
        이 경우 더 구체적인 하위 CWE는 "관련 CWE" 또는 "세부 후보 CWE"로만 언급하세요.

        4. 최종 CWE는 다음 기준을 순서대로 고려하여 선택하세요.
        - 사용자 코드와 가장 유사하게 검색된 참고 지식의 CWE
        - 코드에서 실제로 발생한 직접 원인
        - 공격자가 조작할 수 있는 입력값, 요청값, 파일, 파라미터 또는 외부 데이터
        - 검증, 제한, 인가, 인증, 예외 처리, 경계값 검사, 길이 제한, 크기 제한, 횟수 제한, 시간 제한 등의 보안 통제 부재 여부
        - 후보 CWE 중 사용자 코드의 취약 패턴을 가장 구체적으로 설명하는 CWE
        - 참고 지식에 명시된 CWE 관계 또는 취약점 설명과의 일치도

        5. 하위 CWE가 존재한다는 이유만으로 최종 CWE를 하위 CWE로 선택하지 마세요. 
        하위 CWE를 선택하려면 사용자 코드의 취약한 동작, 취약 원인, 공격 시나리오가 해당 하위 CWE의 설명과 명확하게 맞아야 합니다.

        6. 상위 CWE는 취약점의 넓은 범주나 결과를 설명할 때 "관련 CWE" 또는 "상위 CWE"로 언급할 수 있습니다. 
        단, 사용자 코드가 특정 하위 CWE보다 상위 CWE의 레슨/패턴과 더 직접적으로 일치한다면 상위 CWE를 최종 CWE로 선택할 수 있습니다.

        7. 보안 개선책에 특정 통제 방법이 포함된다는 이유만으로 최종 CWE를 변경하지 마세요. 
        최종 CWE는 "어떤 방식으로 고쳤는가"가 아니라 "사용자 코드에서 어떤 취약 원인이 실제로 발생했는가"를 기준으로 선택해야 합니다.

        8. 하나의 코드에서 여러 취약점이 독립적으로 존재하는 경우, 하나의 최종 CWE로 억지로 합치지 말고 취약점 항목별로 각각의 최종 CWE와 관련 CWE를 분리해서 작성하세요.

        9. 참고 지식과 사용자 코드가 부분적으로만 일치하는 경우, 확실한 취약점만 보고하세요. 
        근거가 부족한 CWE는 최종 CWE로 단정하지 말고 "가능성 있음", "관련 후보" 수준으로만 언급하세요.

        10. 최종 출력에는 반드시 다음을 분리해서 작성하세요.
        - 최종 CWE
        - 관련 CWE 또는 상위/하위 후보 CWE
        - 최종 CWE로 판단한 이유
        - 관련 CWE를 최종 CWE로 선택하지 않은 이유

        [자동 채점을 위한 추가 규칙]
        마지막으로, 당신이 판단한 최종 CWE 번호를 반드시 <CWE>CWE-XXX</CWE> 형태의 태그로 감싸서 답변 맨 마지막에 단 하나만 출력하세요. (예: <CWE>CWE-798</CWE>) 
        취약점이 없다면 <CWE>None</CWE>을 출력하세요.


        [이번 분석에서 사용 가능한 CWE 범위]
        {allowed_cwes_text}

        [DB 근거 제한 규칙]
        1. 최종 CWE로 확정할 수 있는 CWE는 반드시
        [이번 분석에서 사용 가능한 CWE 범위]에 포함된 CWE만 허용됩니다.

        2. 위 목록에 없는 CWE를 별도의 최종 취약점으로 확정하거나,
        해당 CWE를 직접 근거로 새로운 개선 코드를 생성하지 마세요.

        3. 단, 최종 CWE의 분류적 이해를 돕기 위한
        상위 CWE, 관련 CWE, 하위 후보 CWE는 보조 설명 수준에서 언급할 수 있습니다.
        이 경우 반드시 "관련 CWE", "상위 CWE", "후보 CWE"처럼
        최종 판정이 아님을 분명히 표시하세요.

        4. 사용자 코드에서 보안상 의심되는 문제가 보이더라도,
        제공된 [참고 지식(Security Knowledge Base)]으로 직접 설명할 수 없다면
        그 문제를 최종 취약점으로 확정하지 마세요.

        5. 검색된 DB 지식과 사용자 코드의 취약 원인이 직접적으로 대응하지 않는다면
        반드시 아래 문장만 출력하세요.

        "저장된 지식 범위 내에서 확정 가능한 취약점을 찾지 못했습니다."

        [참고 지식(Security Knowledge Base)]
        {retrieved_context}

        [분석할 코드(Source Code)]
        {user_code}
    """

    try:
        response = genai_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        result_text = response.text or ""

        # Gemini가 보류 응답을 낸 경우
        if NO_FINDING_MESSAGE in result_text:
            print("\n================ [AI 분석 결과] ================")
            print(NO_FINDING_MESSAGE)
            print("================================================\n")

            save_analysis_report(
                target_file=target_file,
                status="NO_CONFIRMED_VULNERABILITY",
                summary=NO_FINDING_MESSAGE,
                failure_stage="gemini_analysis_abstained",
                result_text=result_text,
                evidence_items=evidence_items,
                matched_results=matched_results,
                verified_candidate_cwes=verified_candidate_cwes,
                verification_raw_response=verification_result.get(
                    "raw_response",
                    "",
                ),
            )
            continue

        # 최종 CWE 추출
        final_cwes = extract_final_cwes_from_result(result_text)

        # 최종 CWE가 없거나, DB 검색 후보 밖이면 차단
        if (
            not final_cwes
            or not set(final_cwes).issubset(
                verified_candidate_cwes
            )
        ):
            print("\n================ [AI 분석 결과] ================")
            print(NO_FINDING_MESSAGE)
            print("================================================\n")

            save_analysis_report(
                target_file=target_file,
                status="RESULT_REJECTED",
                summary=(
                    "Gemini 결과에서 유효한 최종 CWE를 확인하지 못했거나, "
                    "최종 CWE가 직접 대응 검증을 통과한 후보 범위를 벗어났습니다."
                ),
                failure_stage="final_cwe_validation",
                final_cwes=final_cwes,
                evidence_items=evidence_items,
                matched_results=matched_results,
                verified_candidate_cwes=verified_candidate_cwes,
                verification_raw_response=verification_result.get(
                    "raw_response",
                    "",
                ),
                model_raw_response=result_text,
            )
            continue
        
        final_mitre_context = build_mitre_context(
        final_cwes,
        mitre_cwe_db
        )

        print("\n================ [AI 분석 결과] ================")
        print(result_text)
        print("================================================\n")

        print("\n=== 📚 [MITRE 공식 기준 보강] ===")
        print(f"최종 CWE exact lookup 대상: {final_cwes}")
        print(final_mitre_context)
        print("================================================\n")

        print("================================================\n")

        # --- 성공 결과 파일 저장 ---
        save_analysis_report(
            target_file=target_file,
            status="DETECTED_AND_PATCHED",
            summary=(
                "DB 근거 직접 대응 검증과 최종 CWE 검증을 통과하여 "
                "취약점 분석 및 개선 코드를 생성했습니다."
            ),
            result_text=result_text,
            final_cwes=final_cwes,
            final_mitre_context=final_mitre_context,
            evidence_items=evidence_items,
            matched_results=matched_results,
            verified_candidate_cwes=verified_candidate_cwes,
            verification_raw_response=verification_result.get(
                "raw_response",
                "",
            ),
        )

    except Exception as e:
        print(f"오류 발생: {e}")

        try:
            save_analysis_report(
                target_file=target_file,
                status="ERROR",
                summary="분석 도중 오류가 발생했습니다.",
                failure_stage="runtime_exception",
                evidence_items=locals().get(
                    "evidence_items",
                    [],
                ),
                matched_results=locals().get(
                    "matched_results",
                    [],
                ),
                verified_candidate_cwes=locals().get(
                    "verified_candidate_cwes",
                    set(),
                ),
                verification_raw_response=(
                    locals()
                    .get("verification_result", {})
                    .get("raw_response", "")
                ),
                model_raw_response=locals().get(
                    "result_text",
                    "",
                ),
                error_message=str(e),
            )
        except Exception as save_error:
            print(
                "⚠️ 오류 결과 파일 저장에도 실패했습니다: "
                f"{save_error}"
            )
        