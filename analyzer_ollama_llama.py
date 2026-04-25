import os
import chromadb
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
import datetime
import ollama  # 구글 genai 대신 로컬 ollama 라이브러리 사용!

# --- 1. DB 셋업 (API 키 필요 없음!) ---
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

try:
    db_clint = chromadb.PersistentClient(path=db_path)
    collection = db_clint.get_collection(name="python_security_lessons")
except Exception as e:
    print(f"DB 연결 실패: {e}")
    exit()

# --- 2. 🌳 트리시터 셋업 (제미나이와 100% 동일) ---
PY_LANGUAGE = Language(tspython.language())
parser = Parser()
parser.language = PY_LANGUAGE

def extract_all_functions(node, source_code, chunks_list):
    if node.type in ["function_definition", "class_definition"]:
        chunk_code = source_code[node.start_byte:node.end_byte]
        chunks_list.append(chunk_code)
    elif node.type == "if_statement":
        if node.parent and node.parent.type == "module":
            chunk_code = source_code[node.start_byte:node.end_byte]
            chunks_list.append(chunk_code)
    for child in node.children:
        extract_all_functions(child, source_code, chunks_list)

def parse_and_chunk(source_code):
    tree = parser.parse(bytes(source_code, "utf8"))
    functions = []
    extract_all_functions(tree.root_node, source_code, functions)
    return functions

# --- 3. 메인 분석 루프 ---
print("=== RAG + Tree-sitter 로컬 보안 분석 (Llama 3.2) ===")
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

    if not os.path.exists(target_file):
        print(f"⚠️ 오류: '{target_file}' 파일을 찾을 수 없습니다. 경로를 다시 확인해주세요.")
        continue

    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            user_code = f.read()
    except Exception as e:
        print(f"⚠️ 파일 읽기 오류: {e}")
        continue

    if not user_code.strip():
        continue

    print(f"\n[1/3] ✂️ Tree-sitter로 '{target_file}' 코드 청킹(Chunking) 진행 중...")
    chunks = parse_and_chunk(user_code)
    
    if not chunks:
        chunks = [user_code]
    
    print("[2/3] 🔍 DB에서 각 함수별로 취약점 패턴 검색 중...")
    retrieved_contexts_set = set()
    DISTANCE_THRESHOLD = 1.5 
    
    db_size = collection.count()
    if db_size == 0:
        print("⚠️ DB가 비어있습니다. 데이터를 먼저 추가해주세요.")
        continue
        
    k = min(3, db_size)

    for i, chunk in enumerate(chunks):
        results = collection.query(query_texts=[chunk], n_results=k)
        if results['metadatas'] and results['metadatas'][0]:
            distances = results['distances'][0]
            metadatas = results['metadatas'][0]
            for j in range(len(metadatas)):
                dist = distances[j]
                if dist < DISTANCE_THRESHOLD:
                    doc = metadatas[j]['full_text']
                    retrieved_contexts_set.add(doc)

    valid_docs_count = len(retrieved_contexts_set)

    if valid_docs_count > 0:
        print(f"\n[3/3] 🧠 {valid_docs_count}개의 고유 지식을 바탕으로 Llama 3.2 정밀 분석을 시작합니다...")
        
        retrieved_context = "\n\n".join(
            [f"--- [참고 지식 {idx+1}] ---\n{doc}" for idx, doc in enumerate(retrieved_contexts_set)]
        )
        
        prompt = f"""
        당신은 파이썬 보안 전문가입니다. 
        사용자가 입력한 코드 전체를 분석하세요.
        
        Hallucination 방지
        1. 제공된 [참고 지식(DB)]들을 복합적으로 참조하여 분석하세요.
        2. [참고 지식(DB)]이 비어있거나 무관하다면 "현재 보안 DB에 일치하는 취약점 패턴이 없어 정확한 분석을 수행할 수 없습니다." 라고만 답변하세요.
        3. 취약점이 발견되더라도, DB에 있는 해결책 예제 코드를 그대로 복사하지 마세요.
        4. 반드시 [사용자 입력 전체 코드]의 문맥을 유지하면서, 취약점만 안전하게 패치한 '사용자 맞춤형 개선 코드'를 작성하세요.
        5. 수정된 코드와 함께 관련 CWE 번호 및 패치 원리를 설명하세요.
        6. 사용자 입력 코드에서 취약점이 발견된 코드는 개별 항목을 만들어서 취약 코드를 똑같이 적어주세요.
        7. 답변은 반드시 '한국어'로 작성해주세요.

        **[참고 지식(DB)]**
        {retrieved_context}
        
        **[사용자 입력 전체 코드]**
        {user_code}
        """
        
        try:
            # 👇 여기서 구글 API 대신 로컬 Ollama를 호출합니다! 👇
            response = ollama.chat(model='llama3.2', messages=[
                {
                    'role': 'user',
                    'content': prompt,
                },
            ])
            result_text = response['message']['content']
            # 👆 ------------------------------------------- 👆

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
                
                # 파일명도 알아보기 쉽게 ollama_llama3.2 로 저장되게 세팅했습니다!
                filename = os.path.join("result", f"result_ollama_llama3.2_{base_name}_{now}.txt")
                
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"=== RAG + 로컬(Llama 3.2) 보안 분석 리포트 ({now}) ===\n")
                    f.write(f"=== 분석 대상 파일: {target_file} ===\n\n")
                    f.write(result_text)
                
                print(f"✅ 분석 결과가 '{filename}' 파일에 성공적으로 저장되었습니다!")

        except Exception as e:
            print(f"오류 발생 (Ollama가 실행 중인지 확인하세요): {e}")
    else:
        print("\n================ [AI 분석 결과] ================")
        print("DB 내에 일치하는 위협 패턴이 없어 분석을 건너뜁니다. (안전하거나 미등록된 패턴)")
        print("================================================\n")