import os
import chromadb

# 1. DB 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

print("=== Snyk의 '객체 속성 수준 인가 취약점(BOPLA)' 지식을 DB에 업데이트합니다 ===")

# 2. ChromaDB 클라이언트 연결
try:
    client = chromadb.PersistentClient(path=db_path)
except Exception as e:
    print(f"DB 초기화 실패: {e}")
    exit()

# 3. 컬렉션 불러오기
collection_name = "python_security_lessons"
collection = client.get_or_create_collection(name=collection_name)

# ==========================================
# 📚 [Snyk: Broken Object Property Level Authorization]
# ==========================================

bopla_doc = """
from flask import Flask, request, jsonify

app = Flask(__name__)

# 가상의 사용자 데이터베이스 모델
users_db = {
    "user123": {
        "username": "john_doe",
        "email": "john@example.com",
        "is_admin": False,
        "balance": 100
    }
}

# 🚨 취약점: 객체 속성 수준 인가 누락 / Mass Assignment (CWE-915)
# 사용자의 요청(JSON)을 필터링 없이 그대로 사용자 객체에 병합(업데이트)함
@app.route('/api/v1/user/<user_id>', methods=['PUT'])
def update_user_profile(user_id):
    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404
        
    user = users_db[user_id]
    update_data = request.json
    
    # 해커가 {"is_admin": True, "balance": 999999} 를 보내면 그대로 덮어씌워짐!
    user.update(update_data)
    
    return jsonify({"message": "프로필이 업데이트 되었습니다.", "user": user})
"""

bopla_meta = {
    "cwe": "CWE-915", # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    "full_text": """
[취약점 명칭] Broken Object Property Level Authorization (객체 속성 수준 인가 취약점 / BOPLA / Mass Assignment)
[CWE 번호] CWE-915 (동적으로 결정된 객체 속성의 부적절한 수정 통제)

[상세 설명]
클라이언트가 전송한 데이터(주로 JSON 객체)를 서버측 객체나 데이터베이스 모델에 바인딩할 때, 허용된 속성(Property)만 수정하도록 제한하지 않아 발생하는 취약점입니다. 
공격자는 프로필 업데이트와 같은 일반적인 API 요청에 `is_admin`, `role`, `balance` 와 같은 내부/민감 속성을 추가하여 전송함으로써 시스템 권한을 탈취하거나 비즈니스 로직을 우회할 수 있습니다.

[해결책 및 개선 코드]
사용자로부터 받은 전체 JSON 객체를 그대로 모델에 업데이트(`update()`, `**kwargs`)해서는 안 됩니다. 
반드시 수정이 허용된 필드(Allowlist)만 명시적으로 추출하여 업데이트하거나, DTO(Data Transfer Object) 및 파이단틱(Pydantic) 모델 등을 사용하여 입력값을 엄격하게 필터링해야 합니다.

**[안전한 코드 예시]**
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

users_db = {
    "user123": {"username": "john_doe", "email": "john@example.com", "is_admin": False, "balance": 100}
}

# 개선: 허용된 필드(Allowlist)만 명시적으로 추출하여 업데이트
@app.route('/api/v1/user/<user_id>', methods=['PUT'])
def update_user_profile_secure(user_id):
    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404
        
    user = users_db[user_id]
    update_data = request.json
    
    # 💡 안전한 로직: 사용자가 수정할 수 있는 필드만 수동으로 추출
    allowed_fields = ['username', 'email']
    
    for field in allowed_fields:
        if field in update_data:
            user[field] = update_data[field]
            
    # is_admin이나 balance 같은 필드는 무시됨
    
    return jsonify({"message": "프로필이 안전하게 업데이트 되었습니다."})
"""
}

# ==========================================
# 💾 [DB에 추가 및 저장]
# ==========================================
try:
    collection.upsert(
        documents=[bopla_doc],
        metadatas=[bopla_meta],
        ids=["snyk_lesson_bopla_mass_assignment"]
    )
    print("\n✅ '객체 속성 수준 인가 취약점(CWE-915)' 지식이 성공적으로 DB에 주입되었습니다!")
    print(f"현재 DB 총 지식 수: {collection.count()}개")
except Exception as e:
    print(f"\n⚠️ 데이터 주입 중 오류가 발생했습니다: {e}")