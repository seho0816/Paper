import os
import datetime
import re
import time
import csv
import json

from google import genai
from dotenv import load_dotenv
from config import TEST_DIR
from rag_engine import RAGEngine

import chromadb
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

# ===========================================================
# 1. 환경 변수 설정 및 Gemini 클라이언트 초기화
# ===========================================================
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("❌ 에러: .env 파일에 GEMINI_API_KEY가 없습니다!")
    exit()

client = genai.Client(api_key=GEMINI_API_KEY)

# 사용할 Gemini 모델
TARGET_MODEL = 'gemini-2.5-pro'

# ===========================================================
# 2. ChromaDB 연결
# ===========================================================
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

try:
    db_client = chromadb.PersistentClient(path=db_path)
    collection = db_client.get_collection(name="python_security_lessons")
    print(f"✅ ChromaDB 연결 완료 (문서 수: {collection.count()})")
except Exception as e:
    print(f"❌ DB 연결 실패: {e}")
    exit()

# ===========================================================
# 3. MITRE CWE 공식 JSON 로드
# ===========================================================
mitre_json_path = os.path.join(current_dir, "knowledge", "mitre_cwe_official.json")

try:
    with open(mitre_json_path, "r", encoding="utf-8-sig") as f:
        mitre_cwe_db = json.load(f)
    print(f"✅ MITRE CWE JSON 로드 완료 ({len(mitre_cwe_db)}개 항목)")
except FileNotFoundError:
    print(f"⚠️ MITRE CWE JSON 파일 없음: {mitre_json_path}")
    mitre_cwe_db = {}
except json.JSONDecodeError as e:
    print(f"⚠️ MITRE CWE JSON 형식 오류: {e}")
    mitre_cwe_db = {}
except Exception as e:
    print(f"⚠️ MITRE CWE JSON 로드 실패: {e}")
    mitre_cwe_db = {}

# ===========================================================
# 4. Tree-sitter 셋업
# ===========================================================
PY_LANGUAGE = Language(tspython.language())
parser = Parser()
parser.language = PY_LANGUAGE


def node_text(node, source_bytes):
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")


def is_main_guard(node, source_bytes):
    text = node_text(node, source_bytes)
    return node.type == "if_statement" and "__name__" in text and "__main__" in text


def extract_module_context(root_node, source_bytes):
    """함수/클래스 밖의 전역 설정 코드를 별도 청크로 추출합니다."""
    module_parts = []
    for child in root_node.children:
        if child.type in ["function_definition", "class_definition", "decorated_definition"]:
            continue
        if child.type == "if_statement" and is_main_guard(child, source_bytes):
            continue
        if child.type in [
            "import_statement", "import_from_statement",
            "assignment", "expression_statement",
            "augmented_assignment", "comment",
        ]:
            text = node_text(child, source_bytes).strip()
            if text:
                module_parts.append(text)
    if not module_parts:
        return None
    return "# [MODULE_CONTEXT]\n" + "\n\n".join(module_parts)


def extract_all_functions(node, source_bytes, chunks_list):
    """함수, 클래스, 데코레이터 포함 함수, main guard를 청크로 추출합니다."""
    if node.type == "decorated_definition":
        chunks_list.append(node_text(node, source_bytes))
        return
    if node.type in ["function_definition", "class_definition"]:
        chunks_list.append(node_text(node, source_bytes))
        return
    elif node.type == "if_statement":
        if node.parent and node.parent.type == "module":
            if is_main_guard(node, source_bytes):
                chunks_list.append(node_text(node, source_bytes))
                return
    for child in node.children:
        extract_all_functions(child, source_bytes, chunks_list)


def parse_and_chunk(source_code):
    """코드를 파싱하여 보안 분석용 청크 리스트를 반환합니다."""
    source_bytes = source_code.encode("utf-8")
    tree = parser.parse(source_bytes)
    root_node = tree.root_node

    chunks = []
    module_context = extract_module_context(root_node, source_bytes)
    if module_context:
        chunks.append(module_context)
    extract_all_functions(root_node, source_bytes, chunks)
    return chunks


# ===========================================================
# 5. RAG 검색 및 MITRE 컨텍스트 생성 헬퍼
# ===========================================================
DISTANCE_THRESHOLD = 1.8
MITRE_TOP_K_PER_CHUNK = 2


def extract_cwes_from_metadata_value(cwe_value):
    if not cwe_value:
        return []
    return re.findall(r"CWE-\d+", str(cwe_value))


def build_mitre_context(candidate_cwes, mitre_cwe_db):
    sections = []
    for cwe in sorted(candidate_cwes):
        info = mitre_cwe_db.get(cwe)
        if not info:
            continue
        parent_cwe = ", ".join(info.get("parent_cwe", [])) or "없음"
        related_cwe = ", ".join(info.get("related_cwe", [])) or "없음"
        sections.append(f"""--- [MITRE 공식 기준: {cwe}] ---
공식명: {info.get("official_title", "")}
추상화 수준: {info.get("abstraction", "")}
취약점 매핑: {info.get("vulnerability_mapping", "")}
공식 요약: {info.get("summary_ko", "")}
공식 완화 방향: {info.get("mitigation_ko", "")}
상위 CWE: {parent_cwe}
관련 CWE: {related_cwe}
Python 관련 메모: {info.get("python_note", "")}
출처: {info.get("source_url", "")}""".strip())

    if not sections:
        return (
            "MITRE JSON에 등록된 공식 기준 정보는 없습니다. "
            "단, Python 취약/개선 예시 DB가 사용자 코드와 명확히 일치하면 "
            "기존 DB를 기준으로 분석을 계속하세요."
        )
    return "\n\n".join(sections)


def get_rag_context_chunked(code_content):
    """
    Tree-sitter로 청킹 후 각 청크별로 ChromaDB를 검색하여
    RAG 컨텍스트 문자열과 MITRE 후보 CWE 세트를 반환합니다.
    """
    chunks = parse_and_chunk(code_content)
    if not chunks:
        chunks = [code_content]

    db_size = collection.count()
    if db_size == 0:
        return "", set()

    k = min(7, db_size)
    retrieved_contexts_set = set()
    mitre_candidate_cwes = set()

    for chunk in chunks:
        results = collection.query(query_texts=[chunk], n_results=k)
        if not (results['metadatas'] and results['metadatas'][0]):
            continue

        distances = results['distances'][0]
        metadatas = results['metadatas'][0]

        for j in range(len(metadatas)):
            if distances[j] >= DISTANCE_THRESHOLD:
                continue
            doc = metadatas[j].get('full_text', '')
            if doc:
                retrieved_contexts_set.add(doc)
            cwe_value = metadatas[j].get('cwe')
            found_cwes = extract_cwes_from_metadata_value(cwe_value)
            if j < MITRE_TOP_K_PER_CHUNK:
                for cwe in found_cwes:
                    if cwe in mitre_cwe_db:
                        mitre_candidate_cwes.add(cwe)

    if not retrieved_contexts_set:
        return "", mitre_candidate_cwes

    retrieved_context = "\n\n".join(
        [f"--- [Python 취약/개선 예시 {idx+1}] ---\n{doc}"
         for idx, doc in enumerate(retrieved_contexts_set)]
    )
    return retrieved_context, mitre_candidate_cwes


# ===========================================================
# 6. Gemini 평가 함수 (Tree-sitter + MITRE + RAG 통합)
# ===========================================================
def evaluate_with_gemini(code_content, ground_truth_cwes):
    """Tree-sitter 청킹 → ChromaDB RAG → MITRE JSON → Gemini 평가"""

    # RAG 검색 (청킹 포함)
    retrieved_context, mitre_candidate_cwes = get_rag_context_chunked(code_content)
    mitre_context = build_mitre_context(mitre_candidate_cwes, mitre_cwe_db)

    # RAG 결과가 없으면 평가 스킵
    if not retrieved_context:
        return {
            'prediction': 'SKIPPED',
            'eval_result': 'FP',
            'inference_time': 0.0,
            'raw_response': 'DB 내 일치하는 패턴 없음 — 평가 스킵'
        }

    prompt = f"""당신은 파이썬 보안 코드 분석 전문가입니다.
아래 [참고 지식]을 바탕으로 [분석 대상 코드]의 취약점을 분석하세요.

[핵심 지시사항]
1. 복붙 금지: DB 예제 코드를 그대로 복사하지 마세요. 반드시 [분석 대상 코드]의 문맥을 유지하면서 패치하세요.
2. 무관함 판단: 참고 지식과 관련이 없으면 억지로 찾지 말고 취약점 없음으로 판단하세요.
3. 정확한 식별: 여러 취약점 중 코드에서 발생한 가장 '직접적인 원인' 하나를 최종 CWE로 선택하세요.
4. 양식 준수: 당신의 답변은 반드시 아래의 [출력 템플릿] 형태를 100% 똑같이 따라서 작성해야 합니다. 다른 말은 덧붙이지 마세요.

[CWE 분류 우선순위 규칙]
1. 참고 지식에 여러 CWE가 포함되어 있을 경우, 사용자 코드와 가장 직접적으로 일치하는 참고 지식의 CWE를 우선 후보로 삼으세요.
2. 후보 CWE들 사이에 부모-자식 관계가 있는 경우, 하위 CWE를 무조건 우선하지 마세요.
3. 최종 CWE는 "어떻게 고쳤는가"가 아니라 "어떤 취약 원인이 실제로 발생했는가"를 기준으로 선택하세요.
4. 하나의 코드에서 여러 독립 취약점이 있으면 억지로 합치지 말고, 각각 최종 CWE를 분리해서 작성하세요.

**[MITRE 공식 CWE 기준]**
{mitre_context}

[참고 지식(Security Knowledge Base)]
{retrieved_context}

[분석 대상 코드]
{code_content}

=========================================
[출력 템플릿] (이 양식을 복사해서 빈칸을 채우세요)

▶ 취약점 분석 및 원리:
(여기에 한국어로 코드의 문제점과 패치 원리 설명)

▶ 맞춤형 개선 코드:
```python
(여기에 기존 코드를 안전하게 수정한 전체 코드 작성)
```

▶ 최종 판단 CWE:
(여기에 <CWE>태그</CWE> 작성)

[자동 채점을 위한 추가 규칙 - 필수]
답변의 가장 마지막에는 반드시 당신이 판단한 최종 CWE 번호를 CWE-XXX 형태의 태그로 감싸서 단 하나만 출력하세요. (예: <CWE>CWE-798</CWE>)
취약점이 없다면 <CWE>None</CWE>을 출력하세요.
"""

    start_time = time.time()
    try:
        response = client.models.generate_content(
            model=TARGET_MODEL,
            contents=prompt
        )
        result_text = response.text
    except Exception as e:
        result_text = f"Error: {e}"
    inference_time = round(time.time() - start_time, 2)

    # <CWE> 태그에서 예측값 추출
    match = re.search(r'<CWE>(.*?)</CWE>', result_text, re.IGNORECASE | re.DOTALL)
    predicted_cwe = match.group(1).strip() if match else "UNKNOWN"

    eval_result = 'TP' if predicted_cwe in ground_truth_cwes else 'FP'

    raw_preview = result_text.replace('\n', ' ').strip()
    if len(raw_preview) > 100:
        raw_preview = raw_preview[:100] + "..."

    return {
        'prediction': predicted_cwe,
        'eval_result': eval_result,
        'inference_time': inference_time,
        'raw_response': raw_preview
    }


# ===========================================================
# 7. 메인 평가 루프
# ===========================================================
def main():
    print(f"=== 🚀 [{TARGET_MODEL}] 논문용 데이터 수집 평가 시스템 시작 (Tree-sitter + MITRE + RAG) ===")

    RESULT_DIR = 'result_int'
    os.makedirs(RESULT_DIR, exist_ok=True)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    model_stats = {'Correct': 0, 'Incorrect': 0, 'total_time': 0.0, 'logs': []}
    csv_data = []
    total_files = len(test_files)

    print(f"\n⏳ [{TARGET_MODEL}] 모델 평가 진행 중... (총 {total_files}개 파일)\n")

    for idx, filename in enumerate(test_files, start=1):
        file_path = os.path.join(TEST_DIR, filename)
        progress = (idx / total_files) * 100
        print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}' 분석 중... ", end='', flush=True)

        # 파일명에서 정답 CWE 추출
        matches = re.findall(r'CWE-\d{3,4}', filename, re.IGNORECASE)
        ground_truth_cwes = matches if matches else ["None"]

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
        except Exception as e:
            print(f"⚠️ 파일 읽기 실패: {e}")
            continue

        result = evaluate_with_gemini(code_content, ground_truth_cwes)

        gt_str = "/".join(ground_truth_cwes)
        match_ox = 'O' if result['eval_result'] == 'TP' else 'X'

        if match_ox == 'O':
            model_stats['Correct'] += 1
            print(f"✅ 정답 (판정: {match_ox} | 시간: {result['inference_time']}s)")
        else:
            model_stats['Incorrect'] += 1
            print(f"❌ 오답 (판정: {match_ox} | 정답: {gt_str} 👉 예측: {result['prediction']} | 시간: {result['inference_time']}s)")

        model_stats['total_time'] += result['inference_time']

        csv_data.append({
            'Model': TARGET_MODEL,
            'Filename': filename,
            'Ground_Truth': gt_str,
            'Prediction': result['prediction'],
            'Match': match_ox,
            'Time_s': result['inference_time'],
            'Memory_MB': 'API'
        })

        log_str = (
            f"📄 {filename} | 정답: {gt_str:<10} | "
            f"예측: {result['prediction']:<10} | 판정: {match_ox} | 시간: {result['inference_time']}s"
        )
        model_stats['logs'].append(log_str)

    # -------------------------------------------------------
    # 결과 저장
    # -------------------------------------------------------
    now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    correct = model_stats['Correct']
    total = total_files
    accuracy = (correct / total * 100) if total > 0 else 0
    avg_time = round(model_stats['total_time'] / total, 2) if total > 0 else 0

    # 텍스트 리포트
    report_filename = os.path.join(RESULT_DIR, f'Eval_Gemini_{now_str}.txt')
    with open(report_filename, mode='w', encoding='utf-8') as rf:
        rf.write("=" * 60 + "\n")
        rf.write(f"📊 [{TARGET_MODEL}] CWE 식별 정확도 평가 리포트 (Tree-sitter + MITRE + RAG)\n")
        rf.write("=" * 60 + "\n\n")
        rf.write(
            f"| Accuracy: {accuracy:.1f}% | Correct: {correct} | "
            f"Incorrect: {total - correct} | Avg Time: {avg_time}s |\n\n"
        )
        rf.write("📝 상세 로그\n")
        rf.write("-" * 60 + "\n")
        for log in model_stats['logs']:
            rf.write(log + "\n")

    # CSV 데이터
    csv_filename = os.path.join(RESULT_DIR, f'Data_Gemini_{now_str}.csv')
    with open(csv_filename, mode='w', encoding='utf-8-sig', newline='') as cf:
        writer = csv.DictWriter(
            cf,
            fieldnames=['Model', 'Filename', 'Ground_Truth', 'Prediction', 'Match', 'Time_s', 'Memory_MB']
        )
        writer.writeheader()
        writer.writerows(csv_data)

    print(f"\n✅ 평가 완료! 요약 리포트: '{report_filename}'")
    print(f"📊 논문용 CSV 데이터: '{csv_filename}'")
    print(f"\n📈 최종 정확도: {accuracy:.1f}% ({correct}/{total}) | 평균 추론 시간: {avg_time}s")


if __name__ == "__main__":
    main()