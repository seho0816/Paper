import os
import json
import re
import chromadb
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
import datetime
import ollama

# --- 1. DB 셋업 ---
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

try:
    db_clint = chromadb.PersistentClient(path=db_path)
    collection = db_clint.get_collection(name="python_security_lessons")
except Exception as e:
    print(f"DB 연결 실패: {e}")
    exit()

# --- 1-1. MITRE CWE 공식 JSON 로드  ---
mitre_json_path = os.path.join(current_dir, "knowledge", "mitre_cwe_official.json")
try:
    with open(mitre_json_path, "r", encoding="utf-8-sig") as f:
        mitre_cwe_db = json.load(f)
    print(f"✅ MITRE CWE JSON 로드 완료")
except Exception as e:
    print(f"⚠️ MITRE CWE JSON 로드 실패: {e}")
    mitre_cwe_db = {}

# --- 2. 🌳 트리시터 셋업  ---
PY_LANGUAGE = Language(tspython.language())
parser = Parser()
parser.language = PY_LANGUAGE

def node_text(node, source_bytes):
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")

def is_main_guard(node, source_bytes):
    text = node_text(node, source_bytes)
    return node.type == "if_statement" and "__name__" in text and "__main__" in text

def extract_module_context(root_node, source_bytes):
    module_parts = []
    for child in root_node.children:
        if child.type in ["function_definition", "class_definition", "decorated_definition"]:
            continue
        if child.type == "if_statement" and is_main_guard(child, source_bytes):
            continue
        if child.type in ["import_statement", "import_from_statement", "assignment", "expression_statement", "augmented_assignment", "comment"]:
            text = node_text(child, source_bytes).strip()
            if text:
                module_parts.append(text)
    if not module_parts:
        return None
    return "# [MODULE_CONTEXT]\n" + "\n\n".join(module_parts)

def extract_all_functions(node, source_bytes, chunks_list):
    if node.type == "decorated_definition":
        chunk_code = node_text(node, source_bytes)
        chunks_list.append(chunk_code)
        return
    if node.type in ["function_definition", "class_definition"]:
        chunk_code = node_text(node, source_bytes)
        chunks_list.append(chunk_code)
        return
    elif node.type == "if_statement":
        if node.parent and node.parent.type == "module":
            if is_main_guard(node, source_bytes):
                chunk_code = node_text(node, source_bytes)
                chunks_list.append(chunk_code)
                return
    for child in node.children:
        extract_all_functions(child, source_bytes, chunks_list)

def parse_and_chunk(source_code):
    source_bytes = source_code.encode("utf-8")
    tree = parser.parse(source_bytes)
    chunks = []
    module_context = extract_module_context(tree.root_node, source_bytes)
    if module_context:
        chunks.append(module_context)
    extract_all_functions(tree.root_node, source_bytes, chunks)
    return chunks

# --- 2-1. 지식 가공 헬퍼 함수 ---
def extract_cwes_from_metadata_value(cwe_value):
    if not cwe_value: return []
    return re.findall(r"CWE-\d+", str(cwe_value))

def build_mitre_context(candidate_cwes, mitre_cwe_db):
    sections = []
    for cwe in sorted(candidate_cwes):
        info = mitre_cwe_db.get(cwe)
        if not info: continue
        parent_cwe = ", ".join(info.get("parent_cwe", [])) or "없음"
        related_cwe = ", ".join(info.get("related_cwe", [])) or "없음"
        sections.append(f"""
--- [MITRE 공식 기준: {cwe}] ---
공식 요약: {info.get("summary_ko", "")}
공식 완화 방향: {info.get("mitigation_ko", "")}
상위 CWE: {parent_cwe}
관련 CWE: {related_cwe}
Python 관련 메모: {info.get("python_note", "")}
""".strip())
    if not sections: return "MITRE JSON에 등록된 공식 기준 정보는 없습니다."
    return "\n\n".join(sections)


# --- 3. 메인 분석 루프 ---
print("=== RAG + Tree-sitter 로컬 보안 분석 (Llama 3.2) ===")

while True:
    print("\n[파일 경로 입력 대기 중...]")
    target_file = input("경로 (종료 'exit'): ").strip()
    if target_file.lower() == 'exit': break
    if not target_file or not os.path.exists(target_file): continue

    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            user_code = f.read()
    except Exception as e:
        print(f"⚠️ 파일 읽기 오류: {e}"); continue

    print(f"\n[1/3] ✂️ Tree-sitter로 '{target_file}' 코드 청킹 진행 중...")
    chunks = parse_and_chunk(user_code)
    if not chunks: chunks = [user_code]

    print("[2/3] 🔍 DB에서 취약점 패턴 검색 중...")
    retrieved_contexts_set = set()
    mitre_candidate_cwes = set()
    DISTANCE_THRESHOLD = 1.8
    
    db_size = collection.count()
    k = min(7, db_size)

    for i, chunk in enumerate(chunks):
        results = collection.query(query_texts=[chunk], n_results=k)
        if results['metadatas'] and results['metadatas'][0]:
            distances = results['distances'][0]
            metadatas = results['metadatas'][0]
            for j in range(len(metadatas)):
                if distances[j] < DISTANCE_THRESHOLD:
                    doc = metadatas[j]['full_text']
                    retrieved_contexts_set.add(doc)
                    found_cwes = extract_cwes_from_metadata_value(metadatas[j].get('cwe'))
                    if j < 2: # 상위 2개만 MITRE 후보로
                        for cwe in found_cwes:
                            if cwe in mitre_cwe_db: mitre_candidate_cwes.add(cwe)

    if len(retrieved_contexts_set) > 0:
        print(f"\n[3/3] 🧠 지식 결합 및 Llama 3.2 정밀 분석 시작...")
        
        retrieved_context = "\n\n".join(
            [f"--- [Python 취약/개선 예시 {idx+1}] ---\n{doc}" for idx, doc in enumerate(retrieved_contexts_set)]
        )
        mitre_context = build_mitre_context(mitre_candidate_cwes, mitre_cwe_db)

        # 💡 [핵심] 로컬 모델 전용 템플릿 강제 프롬프트
        prompt = f"""당신은 파이썬 보안 코드 분석 전문가입니다.
        아래 [참고 지식]을 바탕으로 [분석 대상 코드]의 취약점을 분석하세요.

        [핵심 지시사항]
        1. 복붙 금지: DB 예제 코드를 그대로 복사하지 마세요. 반드시 [분석 대상 코드]의 문맥을 유지하면서 패치하세요.
        2. 무관함 판단: 참고 지식과 관련이 없으면 억지로 찾지 말고 취약점 없음으로 판단하세요.
        3. 정확한 식별: 여러 취약점 중 코드에서 발생한 가장 '직접적인 원인' 하나를 최종 CWE로 선택하세요.
        4. 양식 준수: 당신의 답변은 반드시 아래의 [출력 템플릿] 형태를 100% 똑같이 따라서 작성해야 합니다. 다른 말은 덧붙이지 마세요.

        [참고 지식 (MITRE 및 DB)]
        {mitre_context}

        {retrieved_context}

        [분석 대상 코드]
        {user_code}

        =========================================
        [출력 템플릿] (이 양식을 복사해서 빈칸을 채우세요)

        ▶ 취약점 분석 및 원리:
        (여기에 한국어로 코드의 문제점과 패치 원리 설명)

        ▶ 맞춤형 개선 코드:
        ```python
        (여기에 기존 코드를 안전하게 수정한 전체 코드 작성)

        ▶ 최종 판단 CWE:(여기에 태그 작성)
        [자동 채점을 위한 추가 규칙 - 필수]
        마지막으로, 당신이 판단한 최종 CWE 번호를 반드시 <CWE>CWE-XXX</CWE> 형태의 태그로 감싸서 답변 맨 마지막에 단 하나만 출력하세요. (예: <CWE>CWE-798</CWE>) 
        취약점이 없다면 <CWE>None</CWE>을 출력하세요.
         """
        
        try:
            response = ollama.chat(model='llama3.2', messages=[{'role': 'user', 'content': prompt}])
            result_text = response['message']['content']

            if "미등록 패턴" in result_text or "취약점이 발견되지 않았습니다" in result_text:
                print("\n================ [AI 분석 결과] ================")
                print("현재 코드에서 보안 DB와 일치하는 취약점이 발견되지 않았습니다.")
                print("================================================\n")
            else:
                print("\n================ [AI 분석 결과] ================")
                print(result_text)
                print("================================================\n")
                
                os.makedirs("result", exist_ok=True)
                now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                base_name = os.path.basename(target_file).replace('.py', '')
                filename = os.path.join("result", f"result_ollama_llama3.2_{base_name}_{now}.txt")
                
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"=== RAG + 로컬(Llama 3.2) 보안 분석 리포트 ({now}) ===\n")
                    f.write(f"=== 분석 대상 파일: {target_file} ===\n\n")
                    f.write(result_text)
                
                print(f"✅ 분석 결과가 '{filename}' 파일에 저장되었습니다!")

        except Exception as e:
            print(f"오류 발생 (Ollama 실행 확인): {e}")
    else:
        print("\n================ [AI 분석 결과] ================")
        print("DB 내에 일치하는 위협 패턴이 없어 분석을 건너뜁니다.")
        print("================================================\n")