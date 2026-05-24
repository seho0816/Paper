import os
import chromadb

# 1. DB 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "rag_db")

print("=== Snyk의 'Uncontrolled Recursion(CWE-674)' 지식을 DB에 저장합니다 ===")

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
# 📚 [Snyk: Uncontrolled Recursion]
# ==========================================

uncontrolled_recursion_doc = '''
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# 🚨 취약점: 제어되지 않는 재귀 호출 (CWE-674)
# 사용자 입력으로 받은 start_path부터 디렉터리를 재귀 탐색하지만,
# 최대 깊이 제한이나 방문한 실제 경로/노드 추적이 없음
# 심볼릭 링크 또는 순환 디렉터리 구조가 있으면 무한 재귀, RecursionError, CPU/RAM 고갈이 발생할 수 있음
@app.route('/api/index-files', methods=['POST'])
def index_files():
    start_path = request.json.get("path")

    indexed_files = []

    def crawl_directory(path):
        for name in os.listdir(path):
            full_path = os.path.join(path, name)

            if os.path.isdir(full_path):
                crawl_directory(full_path)
            else:
                indexed_files.append(full_path)

    crawl_directory(start_path)

    return jsonify({
        "indexed_count": len(indexed_files),
        "files": indexed_files
    })
'''

uncontrolled_recursion_meta = {
    "cwe": "CWE-674",
    "full_text": '''
[취약점 명칭] Uncontrolled Recursion (제어되지 않는 재귀 호출)
[CWE 번호] CWE-674 (제어되지 않는 재귀)

[상세 설명]
Uncontrolled Recursion은 재귀 함수가 종료 조건에 도달하지 못하거나, 순환 구조를 탐색하면서 이미 방문한 노드·경로를 다시 방문해 자기 자신을 반복 호출할 때 발생하는 취약점입니다. 이 경우 호출 스택이 계속 증가하여 RecursionError, CPU 사용량 증가, 메모리 고갈, 서비스 거부(DoS)로 이어질 수 있습니다.

본 지식은 CWE-674의 모든 재귀 관련 문제를 포괄적으로 다루는 것이 아니라, Snyk의 Uncontrolled Recursion 레슨에서 제시한 취약 원리를 기반으로, 사용자 입력 또는 외부 환경이 제공한 디렉터리·트리·그래프·중첩 데이터 구조를 재귀적으로 탐색하면서 최대 깊이 제한, 방문 기록, 순환 탐지 없이 자기 자신을 반복 호출하는 Python 코드 패턴을 중심으로 저장합니다.

예를 들어 파일 인덱싱 기능에서 사용자가 전달한 시작 경로를 기준으로 `os.listdir()`로 하위 항목을 탐색하고, `os.path.isdir()`가 참이면 무조건 `crawl_directory(full_path)`를 다시 호출하는 구조가 있을 수 있습니다. 이때 심볼릭 링크가 부모 디렉터리나 이미 방문한 디렉터리를 다시 가리키면, 함수는 같은 구조를 반복해서 내려가며 호출 스택과 시스템 자원을 계속 소비할 수 있습니다.

Snyk 레슨에서도 순환 심볼릭 링크를 포함한 디렉터리 구조에서 프로그램이 같은 경로를 이미 방문했는지 알지 못한 채 재귀 호출을 반복하는 상황을 설명합니다.

단순히 함수가 자기 자신을 호출한다는 이유만으로 CWE-674로 판단해서는 안 됩니다. 이 패턴은 외부 입력 또는 공격자가 조작 가능한 디렉터리, 트리, 그래프, 중첩 데이터 구조를 따라 재귀적으로 탐색하면서, 최대 깊이 제한이나 방문한 노드·경로 추적 없이 자기 자신을 반복 호출하는 경우를 중심으로 판단합니다.

명확한 base case가 있고, 입력 크기나 재귀 깊이가 제한되며, 이미 방문한 노드·경로·inode·realpath 등을 추적하여 순환 구조를 차단하는 경우에는 본 지식과 직접 대응하지 않습니다. 또한 고정된 내부 데이터에 대한 짧고 제한된 재귀, 피보나치 예제처럼 학습용으로 종료 조건이 명확한 재귀 함수는 본 지식과 직접 대응하지 않습니다.

CWE-400은 재귀로 인해 발생할 수 있는 자원 고갈 결과를 포괄하는 관련 후보이고, CWE-770은 제한 없는 리소스 사용의 넓은 범주입니다. 그러나 본 지식은 재귀 호출의 종료 조건·깊이 제한·순환 탐지 부재가 직접 원인이므로 CWE-674를 대표 CWE로 저장합니다.

[해결책 및 개선 코드]
재귀적으로 외부 구조를 탐색할 때는 반드시 최대 깊이 제한과 방문 기록을 함께 사용해야 합니다. 깊이 제한은 비정상적으로 깊은 구조로 인한 호출 스택 증가를 막고, 방문 기록은 심볼릭 링크나 그래프 순환처럼 같은 노드를 반복 방문하는 문제를 차단합니다.

Snyk 레슨도 안전한 디렉터리 크롤러는 깊이 제한과 방문 inode 집합을 함께 사용하여 매우 깊은 구조와 순환 구조를 모두 방어해야 한다고 설명합니다.

**[안전한 코드 예시 (깊이 제한 + realpath 방문 기록)]**
```python
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_DEPTH = 20

@app.route('/api/index-files-secure', methods=['POST'])
def index_files_secure():
    start_path = request.json.get("path")

    if not start_path:
        return jsonify({"error": "path가 필요합니다."}), 400

    indexed_files = []
    visited_paths = set()

    def crawl_directory_secure(path, depth):
        # 💡 안전한 로직 1:
        # 재귀 깊이가 허용 범위를 넘으면 중단
        if depth > MAX_DEPTH:
            return

        real_path = os.path.realpath(path)

        # 💡 안전한 로직 2:
        # 이미 방문한 실제 경로라면 순환 구조로 보고 중단
        if real_path in visited_paths:
            return

        visited_paths.add(real_path)

        try:
            entries = os.listdir(real_path)
        except (OSError, PermissionError):
            return

        for name in entries:
            full_path = os.path.join(real_path, name)

            if os.path.isdir(full_path):
                crawl_directory_secure(full_path, depth + 1)
            else:
                indexed_files.append(full_path)

    crawl_directory_secure(start_path, 0)

    return jsonify({
        "indexed_count": len(indexed_files),
        "files": indexed_files
    })
[안전한 코드 예시 (inode 기반 순환 탐지)]
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_DEPTH = 20

@app.route('/api/index-files-inode-secure', methods=['POST'])
def index_files_inode_secure():
    start_path = request.json.get("path")

    if not start_path:
        return jsonify({"error": "path가 필요합니다."}), 400

    indexed_files = []
    visited_inodes = set()

    def crawl_directory_inode_secure(path, depth):
        if depth > MAX_DEPTH:
            return

        try:
            stat_info = os.stat(path)
        except (OSError, PermissionError):
            return

        node_key = (stat_info.st_dev, stat_info.st_ino)

        # 💡 안전한 로직:
        # 같은 device/inode 조합을 다시 방문하면 순환 구조로 보고 중단
        if node_key in visited_inodes:
            return

        visited_inodes.add(node_key)

        try:
            entries = os.listdir(path)
        except (OSError, PermissionError):
            return

        for name in entries:
            full_path = os.path.join(path, name)

            if os.path.isdir(full_path):
                crawl_directory_inode_secure(full_path, depth + 1)
            else:
                indexed_files.append(full_path)

    crawl_directory_inode_secure(start_path, 0)

    return jsonify({
        "indexed_count": len(indexed_files),
        "files": indexed_files
    })
    '''
}
try:
    collection.upsert(
    documents=[uncontrolled_recursion_doc],
    metadatas=[uncontrolled_recursion_meta],
    ids=["snyk_lesson_uncontrolled_recursion_directory_crawler"]
    )

    print("\n✅ 'Uncontrolled Recursion(CWE-674)' 지식이 성공적으로 DB에 저장되었습니다!")
    print(f"현재 DB 총 지식 수: {collection.count()}개")

except Exception as e:
    print(f"\n⚠️ 데이터 저장 중 오류가 발생했습니다: {e}")