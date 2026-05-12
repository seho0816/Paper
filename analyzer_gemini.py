import os
import json
import re
import chromadb
from google import genai
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
from dotenv import load_dotenv

# --- 1. API 및 DB 셋업 ---
load_dotenv()
api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("⚠️ 오류: .env 파일에 'GEMINI_API_KEY'가 없습니다!")
    exit()
genai_client = genai.Client(api_key=api_key)


current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

try:
    db_clint = chromadb.PersistentClient(path=db_path)
    collection = db_clint.get_collection(name="python_security_lessons")
except Exception as e:
    print(f"DB 연결 실패: {e}")
    exit()

# --- 1-1. MITRE CWE 공식 JSON 로드 ---
mitre_json_path = os.path.join(current_dir, "knowledge", "mitre_cwe_official.json")

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
    검색 결과에서 나온 일부 CWE 후보를 기준으로
    MITRE JSON 공식 지식을 exact lookup하여 프롬프트용 문자열로 구성합니다.
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
        return (
            "MITRE JSON에 등록된 공식 기준 정보는 없습니다. "
            "단, Python 취약/개선 예시 DB가 사용자 코드와 명확히 일치하면 "
            "기존 DB를 기준으로 분석을 계속하세요."
        )

    return "\n\n".join(sections)

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
    retrieved_contexts_set = set() # 중복 방지용 Set
    mitre_candidate_cwes = set()  # MITRE JSON 조회용 후보 CWE
    DISTANCE_THRESHOLD = 1.8
    MITRE_TOP_K_PER_CHUNK = 2
    
    db_size = collection.count()
    if db_size == 0:
        print("⚠️ DB가 비어있습니다. 데이터를 먼저 추가해주세요.")
        continue
        
    k = min(7, db_size) # 각 청크당 상위 3개 검색

    # 각 조각난 함수별로 DB 검색 수행
    for i, chunk in enumerate(chunks):
    # 1. 현재 청크에 대해 쿼리 실행
        results = collection.query(query_texts=[chunk], n_results=k)

    # 2. 결과 처리 로직이 반드시 for 루프 '안쪽'에 있어야 합니다!
        if results['metadatas'] and results['metadatas'][0]:
            distances = results['distances'][0]
            metadatas = results['metadatas'][0]

        for j in range(len(metadatas)):
            dist = distances[j]

            # 설정한 유사도 거리(DISTANCE_THRESHOLD)보다 가까운 것만 처리
            if dist < DISTANCE_THRESHOLD:
                doc = metadatas[j]['full_text']
                retrieved_contexts_set.add(doc)

                cwe_value = metadatas[j].get('cwe')
                found_cwes = extract_cwes_from_metadata_value(cwe_value)

                # ✅ 이제 i+1이 1, 2, 3, 4 순서대로 찍히게 됩니다.
                print(f"  📍 [청크 {i+1}] CWE={cwe_value} 유사도 거리={dist:.4f}")

                # MITRE JSON 조회 후보 추가
                if j < MITRE_TOP_K_PER_CHUNK:
                    for cwe in found_cwes:
                        if cwe in mitre_cwe_db:
                            mitre_candidate_cwes.add(cwe)

    valid_docs_count = len(retrieved_contexts_set)

    if valid_docs_count > 0:
        print(f"\n[3/3] 🧠 {valid_docs_count}개의 고유 지식을 바탕으로 AI 정밀 분석을 시작합니다...")
        
        retrieved_context = "\n\n".join(
    [f"--- [Python 취약/개선 예시 {idx+1}] ---\n{doc}" for idx, doc in enumerate(retrieved_contexts_set)]
)

        mitre_context = build_mitre_context(mitre_candidate_cwes, mitre_cwe_db)

        print("\n=== 📚 [디버그] MITRE JSON 공식 기준 조회 결과 ===")
        print(f"MITRE 조회 후보 CWE: {sorted(mitre_candidate_cwes)}")
        print(mitre_context)
        print("================================================\n")
        
        prompt = f"""
        당신은 파이썬 보안 전문가입니다. 
        사용자가 입력한 코드 전체를 분석하세요.
        
        Hallucination 방지
        1. 제공된 [참고 지식(DB)]들을 복합적으로 참조하여 분석하세요.
        2. [참고 지식(DB)]이 비어있거나 무관하다면 "현재 보안 DB에 일치하는 취약점 패턴이 없어 정확한 분석을 수행할 수 없습니다." 라고만 답변하세요.
        3. 취약점이 발견되더라도, DB에 있는 해결책 예제 코드를 그대로 복사하지 마세요.
        4. 반드시 [사용자 입력 전체 코드]의 문맥을 유지하면서, 취약점만 안전하게 패치한 '사용자 맞춤형 개선 코드'를 작성하세요. 개선 코드는 함수명을 변경하지 마세요.
        5. 수정된 코드와 함께 관련 CWE 번호 및 패치 원리를 설명하세요.
        6. 사용자 입력 코드에서 취약점이 발견된 코드는 개별 항목을 만들어서 취약 코드를 똑같이 적어주세요.

        [지식 사용 규칙]
        1. MITRE 공식 CWE 기준은 CWE 번호, 공식명, 상위/관련 CWE, 최종 CWE 판단 기준을 보강하는 데 사용하세요.
        2. Python 취약/개선 예시 DB는 Python 코드 패턴 탐지와 사용자 맞춤형 개선 코드 작성에 사용하세요.
        3. MITRE 공식 기준 정보가 없는 후보 CWE라도, Python 취약/개선 예시 DB가 사용자 코드와 명확히 일치하면 분석을 중단하지 말고 기존 DB를 기준으로 분석하세요.
        4. MITRE 공식 기준은 보조 기준이며, 사용자 코드와 직접 관련 없는 MITRE 항목을 최종 CWE로 단정하지 마세요.

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

        **[MITRE 공식 CWE 기준]**
        {mitre_context}


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
            result_text = response.text
            

            if "미등록 패턴" in result_text or "취약점이 발견되지 않았습니다" in result_text:
                print("\n================ [AI 분석 결과] ================")
                print("현재 코드에서 보안 DB와 일치하는 취약점이 발견되지 않았습니다.")
                print("================================================\n")
            else:
                print("\n================ [AI 분석 결과] ================")
                print(result_text)
                print("================================================\n")
                
                # --- 👇 여기서부터 파일 저장 코드 추가 👇 ---
                import datetime
                import os
                
                os.makedirs("result", exist_ok=True)
                now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                # 파일명에 분석한 소스코드의 파일명도 함께 넣어주면 구분하기 훨씬 좋습니다!
                base_name = os.path.basename(target_file).replace('.py', '')
                filename = os.path.join("result", f"result_gemini_{base_name}_{now}.txt")
                
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"=== RAG + Gemini 보안 분석 리포트 ({now}) ===\n")
                    f.write(f"=== 분석 대상 파일: {target_file} ===\n\n")
                    f.write(result_text)
                
                print(f"✅ 분석 결과가 '{filename}' 파일에 성공적으로 저장되었습니다!")
                # --- 👆 여기까지 파일 저장 코드 끝 👆 ---

        except Exception as e:
            print(f"오류 발생: {e}")
    else:
        print("\n================ [AI 분석 결과] ================")
        print("DB 내에 일치하는 위협 패턴이 없어 분석을 건너뜁니다. (안전하거나 미등록된 패턴)")
        print("================================================\n")