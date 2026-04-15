import os
import chromadb

# 1. DB 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

print("=== 누락된 CWE 키 업데이트를 시작합니다 ===")

# 2. ChromaDB 클라이언트 연결
try:
    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_collection(name="python_security_lessons")
except Exception as e:
    print(f"DB 로드 실패: {e}")
    exit()

# 3. 업데이트할 타겟 ID
target_id = "snyk_lesson_cwe343_predictable_ids"

# 4. 기존 데이터 불러오기
result = collection.get(ids=[target_id])

if result['metadatas'] and len(result['metadatas']) > 0:
    # 기존 메타데이터 가져오기
    meta = result['metadatas'][0]
    
    # 누락된 cwe 키 추가
    meta['cwe'] = 'CWE-343'
    
    # 5. DB에 업데이트 적용
    collection.update(
        ids=[target_id],
        metadatas=[meta]
    )
    print("✅ 성공적으로 4번(CWE-343) 메타데이터에 'cwe' 키를 추가했습니다!")
else:
    print("⚠️ 해당 ID를 찾을 수 없습니다. (ID를 확인해 주세요)")