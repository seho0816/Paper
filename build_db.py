import os
import chromadb

# 1. DB 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

print("=== 강화된 'CWE-770 (제한 및 스로틀링 누락)' 지식을 DB에 업데이트합니다 ===")

client = chromadb.PersistentClient(path=db_path)
collection = client.get_or_create_collection(name="python_security_lessons")

# ==========================================
# 📚 [Snyk: No Rate Limiting & Resource Limits (강화판)]
# ==========================================

cwe770_enhanced_doc = """
from flask import Flask, request

app = Flask(__name__)

# 🚨 취약점 1: 요청 횟수 제한(Rate Limiting) 누락 (CWE-770 / 스로틀링 부재)
# 해커가 초당 수천 번의 로그인 시도(Brute Force)를 해도 막을 방법이 없음
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    # 비밀번호 확인 로직 (제한 없이 계속 확인해 줌)
    return {"status": "failed"}

# 🚨 취약점 2: 파일 업로드 크기 제한 누락 (CWE-770 / 리소스 할당 제한 부재)
# app.config['MAX_CONTENT_LENGTH']가 없어 10GB짜리 파일을 올려도 서버가 메모리에 올리려 시도함
@app.route('/api/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save(f"/tmp/{file.filename}")
    return "업로드 성공"

# 🚨 취약점 3: 데이터 생성 API 스로틀링 누락 (CWE-770 / 데이터베이스 자원 고갈)
# 댓글 작성, 게시글 생성 등의 API에 쓰기 제한이 없어 해커가 매크로로 DB 스토리지와 커넥션을 고갈시킴 (도배/Spam)
@app.route('/profile/<int:profile_id>/comments', methods=['POST'])
def add_comment(profile_id):
    comment_txt = request.form["comment"]
    # 아무런 제한(Rate Limiting) 없이 1초에 수만 번 호출되어도 그대로 DB에 Insert 됨
    # db.session.add(Comment(comment_txt, profile_id))
    # db.session.commit()
    return "댓글 작성 성공"
"""

cwe770_enhanced_meta = {
    "cwe": "CWE-770",
    "full_text": """
[취약점 명칭] Allocation of Resources Without Limits or Throttling (제한 없는 리소스 할당 / 비율 제한 없음)
[CWE 번호] CWE-770

[상세 설명]
사용자의 요청(네트워크 대역폭, 파일 시스템 공간, API 호출 횟수, DB 쓰기 작업 등)에 대해 서버가 할당 한도나 스로틀링(Throttling)을 설정하지 않아 발생하는 취약점입니다.
해커는 이를 악용하여 무차별 대입 공격(Brute Force), 거대한 파일을 업로드하여 서버 공간 마비, 혹은 댓글/게시글 생성 API를 매크로로 무한 호출하여 데이터베이스 스토리지와 커넥션을 고갈시키는 스팸(Spamming) 공격을 수행할 수 있습니다.

[해결책 및 개선 코드]
1. **API 요청 비율 제한 (Rate Limiting):** 파이썬의 `Flask-Limiter` 등을 사용하여 로그인 시도뿐만 아니라, **데이터를 생성(Insert)하는 API(댓글, 게시글 등)에도 반드시 클라이언트 IP당 호출 횟수(Throttling)를 제한**해야 합니다.
2. **파일 크기 제한:** 프레임워크 레벨에서 한 번에 받을 수 있는 최대 페이로드 크기를 제한해야 합니다.

**[안전한 코드 예시]**
```python
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# 개선 1: 페이로드 및 파일 업로드 크기 제한
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# 개선 2: Flask-Limiter를 사용한 비율 제한(Throttling) 설정
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute") # 로그인 시도 제한
def login():
    return {"status": "failed"}

@app.route('/profile/<int:profile_id>/comments', methods=['POST'])
@limiter.limit("3 per minute") # 개선 3: 댓글 작성 등 DB 데이터를 생성하는 API에도 도배 방지 제한 추가
def add_comment(profile_id):
    comment_txt = request.form["comment"]
    # 안전하게 보호되는 DB 저장 로직
    return "댓글 작성 성공"

@app.route('/api/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save(f"/tmp/{file.filename}")
    return "업로드 성공"
    """
}
try:
    collection.upsert(
    documents=[cwe770_enhanced_doc],
    metadatas=[cwe770_enhanced_meta],
    ids=["snyk_lesson_cwe770_rate_limiting_and_allocation"]
)
    print("\n✅ CWE-770 (데이터 생성 API 도배 방지 내용 포함) 지식이 성공적으로 업데이트되었습니다!")
except Exception as e:
    print(f"\n⚠️ 데이터 주입 중 오류가 발생했습니다: {e}")