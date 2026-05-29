import chromadb

CHROMA_DIR = "./analyzer/rag_db"
COLLECTION_NAME = "python_security_lessons"

CWE_ID = "cwe_759_unsalted_password_hash_sha256"

document = """
from flask import Flask, request
import hashlib
import sqlite3

app = Flask(__name__)

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username")
    password = request.form.get("password")

    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users(username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    conn.commit()
    conn.close()

    return "signup complete"
""".strip()

full_text = """
[취약점 명칭]
Salt 없는 비밀번호 해시 저장

[CWE 번호]
CWE-759

[상세 설명]
사용자 비밀번호를 저장할 때 salt 없이 단방향 해시 함수만 적용하면,
동일한 비밀번호는 항상 동일한 해시값을 가지게 된다.
이 경우 공격자는 레인보우 테이블, 사전 공격, 대량 대입 공격을 통해 원문 비밀번호를 추측하기 쉬워진다.
SHA-256처럼 일반적으로 안전한 해시 함수라도, 비밀번호 저장 용도로 salt와 반복 연산 없이 직접 사용하면 부적절하다.

[탐지 범위]
- request.form, request.json 등으로 받은 password 값을 hashlib.sha256, hashlib.md5, hashlib.sha1 등으로 직접 해시하여 저장하는 경우
- 비밀번호마다 고유한 salt를 생성하지 않고 단순 해시값만 DB에 저장하는 경우
- PBKDF2, bcrypt, scrypt, Argon2, werkzeug.generate_password_hash 같은 비밀번호 저장 전용 함수를 사용하지 않는 경우
- 예: password_hash = hashlib.sha256(password.encode()).hexdigest()
- 예: password_hash = hashlib.md5(password.encode()).hexdigest()
- 예: cursor.execute(..., (username, password_hash))

[잡지 말아야 할 코드]
- werkzeug.security.generate_password_hash(password)를 사용하는 코드
- bcrypt.hashpw(password, bcrypt.gensalt())를 사용하는 코드
- hashlib.pbkdf2_hmac()처럼 salt와 충분한 반복 횟수를 사용하는 코드
- argon2, scrypt 등 비밀번호 저장 전용 알고리즘을 사용하는 코드
- 비밀번호가 아닌 파일 체크섬, 캐시 키, 중복 확인용 해시는 이 문서에서 직접 탐지하지 않는다.
- MD5/SHA1 같은 약한 해시를 토큰, 서명, 무결성 검증 등 일반 보안 목적으로 사용하는 경우는 CWE-328로 분류한다.
- 비밀번호를 아예 해시하지 않고 평문으로 저장하는 경우는 CWE-312로 분류한다.

[취약 코드 예시]
from flask import Flask, request
import hashlib
import sqlite3

app = Flask(__name__)

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username")
    password = request.form.get("password")

    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users(username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    conn.commit()
    conn.close()

    return "signup complete"

[개선 코드 예시]
from flask import Flask, request
import sqlite3
from werkzeug.security import generate_password_hash

app = Flask(__name__)

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username")
    password = request.form.get("password")

    password_hash = generate_password_hash(password)

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users(username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    conn.commit()
    conn.close()

    return "signup complete"

[패치 원리]
비밀번호 저장에는 단순 해시 함수가 아니라 salt와 반복 연산을 포함한 비밀번호 저장 전용 알고리즘을 사용해야 한다.
각 비밀번호마다 고유한 salt를 적용하면 동일한 비밀번호도 서로 다른 해시값을 갖게 되어 레인보우 테이블 공격을 어렵게 만든다.
또한 반복 연산 또는 비용 인자를 적용하면 공격자가 대량의 후보 비밀번호를 빠르게 대입하기 어려워진다.
Werkzeug의 generate_password_hash, bcrypt, scrypt, Argon2, PBKDF2 같은 방식은 이러한 방어 요소를 제공한다.

[검증 등급]
B

[참고 출처]
- MITRE CWE-759: Use of a One-Way Hash without a Salt
- OWASP Password Storage Cheat Sheet
- Werkzeug security password hashing documentation
""".strip()


def main():
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    collection = client.get_collection(COLLECTION_NAME)

    print(f"현재 전체 문서 수: {collection.count()}")

    existing = collection.get(
        where={"cwe": "CWE-759"},
        include=["documents", "metadatas"]
    )

    print(f"기존 CWE-759 문서 수: {len(existing['ids'])}")

    if existing["ids"]:
        target_id = existing["ids"][0]
        print(f"수정 대상 ID: {target_id}")

        collection.update(
            ids=[target_id],
            documents=[document],
            metadatas=[{
                "cwe": "CWE-759",
                "full_text": full_text
            }]
        )

        print("기존 CWE-759 문서를 salt 없는 비밀번호 해시 저장 패턴으로 수정했습니다.")

    else:
        collection.add(
            ids=[CWE_ID],
            documents=[document],
            metadatas=[{
                "cwe": "CWE-759",
                "full_text": full_text
            }]
        )

        print("CWE-759 문서가 없어 새로 추가했습니다.")

    check = collection.get(
        where={"cwe": "CWE-759"},
        include=["documents", "metadatas"]
    )

    print("\n=== 수정 후 CWE-759 확인 ===")
    for i, doc_id in enumerate(check["ids"]):
        print(f"ID: {doc_id}")
        print("DOCUMENT:")
        print(check["documents"][i][:700])
        print("\nFULL_TEXT:")
        print(check["metadatas"][i]["full_text"][:1200])
        print("=" * 80)


if __name__ == "__main__":
    main()