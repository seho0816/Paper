import os
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

# --- 2. 🌳 트리시터 셋업 ---
PY_LANGUAGE = Language(tspython.language())
parser = Parser()
parser.language = PY_LANGUAGE

def extract_all_functions(node, source_code, chunks_list):
    """트리를 탐색하며 함수, 클래스, 주요 글로벌 블록을 모두 추출합니다."""
    
    # 1. 함수나 클래스인 경우 통째로 잘라서 저장
    if node.type in ["function_definition", "class_definition"]:
        chunk_code = source_code[node.start_byte:node.end_byte]
        chunks_list.append(chunk_code)
        
    # 2. if __name__ == "__main__": 같은 글로벌 조건문 블록도 잘라서 저장
    elif node.type == "if_statement":
        # 최상단(module 바로 아래)에 있는 if문만 잡기 위한 간단한 필터링
        if node.parent and node.parent.type == "module":
            chunk_code = source_code[node.start_byte:node.end_byte]
            chunks_list.append(chunk_code)

    # 3. 자식 노드들도 계속 탐색
    for child in node.children:
        extract_all_functions(child, source_code, chunks_list)

def parse_and_chunk(source_code):
    """코드를 파싱하여 함수 단위 청크 리스트를 반환합니다."""
    tree = parser.parse(bytes(source_code, "utf8"))
    functions = []
    extract_all_functions(tree.root_node, source_code, functions)
    return functions

# --- 3. 메인 분석 루프 ---
print("=== RAG + Tree-sitter 파이썬 보안 분석 시스템 ===")
print("분석할 코드를 입력하세요. 입력을 마치려면 'END'를, 종료하려면 'exit'을 입력하세요.")

while True:
    print("\n[코드 입력 대기 중...]")
    user_lines = []
    
    while True:
        line = input()
        if line.strip().upper() == 'END':
            break
        if line.strip().lower() == 'exit':
            print("프로그램을 종료합니다.")
            exit()
        user_lines.append(line)
    
    user_code = "\n".join(user_lines)
    if not user_code.strip():
        continue

    print("\n[1/3] ✂️ Tree-sitter로 코드 청킹(Chunking) 진행 중...")
    chunks = parse_and_chunk(user_code)
    
    # 함수가 없는 단순 스크립트라면 전체 코드를 하나의 청크로 사용
    if not chunks:
        chunks = [user_code]
        print(" -> 함수 구조가 없어 전체 코드를 단일 블록으로 분석합니다.")
    else:
        print(f" -> 총 {len(chunks)}개의 함수/메서드를 식별하여 분리했습니다!\n")
        
        # ==========================================
        # 🛠️ [디버그] 추출된 청크(함수) 내용 출력 로직
        # ==========================================
        print("=== 🛠️ [디버그] Tree-sitter 파싱 결과 확인 ===")
        for i, chunk in enumerate(chunks):
            print(f"▶️ [청크 {i+1}]")
            
            # 보기 좋게 청크의 각 줄 앞에 들여쓰기(| )를 추가해서 출력합니다.
            chunk_lines = chunk.split('\n')
            for line in chunk_lines:
                print(f"  | {line}")
            print("-" * 50)
        print("==============================================\n")

    print("[2/3] 🔍 DB에서 각 함수별로 취약점 패턴 검색 중...")
    retrieved_contexts_set = set() # 중복 방지용 Set
    DISTANCE_THRESHOLD = 1.5 
    
    db_size = collection.count()
    if db_size == 0:
        print("⚠️ DB가 비어있습니다. 데이터를 먼저 추가해주세요.")
        continue
        
    k = min(3, db_size) # 각 청크당 상위 3개 검색

    # 각 조각난 함수별로 DB 검색 수행
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
                    print(f"  📍 [청크 {i+1}]에서 잠재적 위협 패턴 감지 (유사도 거리: {dist:.4f})")

    valid_docs_count = len(retrieved_contexts_set)

    if valid_docs_count > 0:
        print(f"\n[3/3] 🧠 {valid_docs_count}개의 고유 지식을 바탕으로 AI 정밀 분석을 시작합니다...")
        
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

        **[참고 지식(DB)]**
        {retrieved_context}
        
        **[사용자 입력 전체 코드]**
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
        except Exception as e:
            print(f"오류 발생: {e}")
    else:
        print("\n================ [AI 분석 결과] ================")
        print("DB 내에 일치하는 위협 패턴이 없어 분석을 건너뜁니다. (안전하거나 미등록된 패턴)")
        print("================================================\n")