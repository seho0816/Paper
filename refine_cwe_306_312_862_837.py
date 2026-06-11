import argparse
import gc
import re
import shutil
from datetime import datetime
from pathlib import Path

import chromadb


CHROMA_DIR = "./rag_db"
COLLECTION_NAME = "python_security_lessons"
EXPECTED_CURRENT_COUNT = 326
AUTO_BACKUP = True

DELETE_IF_PRESENT = {
    "cwe_862_admin_metrics_endpoint_without_auth": "CWE-862",
}


PATTERNS = [
    {
        "id": "cwe_306_admin_backup_no_authentication",
        "cwe": "CWE-306",
        "document": '''from flask import Flask, send_file

app = Flask(__name__)


@app.get("/admin/backup/download")
def download_backup():
    backup_path = "/var/backups/app/database.dump"

    return send_file(
        backup_path,
        as_attachment=True,
    )
''',
        "full_text": '''[취약점 명칭]
외부 HTTP 관리자 백업 다운로드 기능의 인증 누락

[CWE 번호]
CWE-306

[상세 설명]
외부 요청으로 직접 호출할 수 있는 HTTP 라우트가 데이터베이스 백업처럼 중요한 기능을 수행하면서 로그인 세션, JWT, API Key 등 호출자의 신원을 확인하지 않으면 익명 사용자가 민감한 기능을 실행할 수 있다. 단순한 내부 함수에 인증 코드가 보이지 않는다는 사실만으로는 이 취약점을 확정하지 않고, 외부 진입점과 중요 기능이 같은 분석 범위에서 확인되어야 한다.

[탐지 범위]
- Flask·FastAPI·Django 등의 HTTP 라우트가 외부 요청으로 직접 호출 가능한 경우
- 해당 라우트가 백업 다운로드, 내부 리포트 Export, 관리자 설정, 대량 개인정보 조회처럼 중요 기능을 수행하는 경우
- 라우트와 분석 가능한 호출 흐름에 로그인 확인, 인증 decorator, JWT·세션·API Key 검증이 없는 경우
- 익명 요청이 중요 기능까지 도달한다는 사실을 코드로 확인할 수 있는 경우

[잡지 말아야 할 코드]
- 일반 service·helper 함수에 current_user 인자가 없다는 이유만으로 인증 누락을 추정하지 않는다.
- 외부 라우트인지 내부 호출 함수인지 확인할 수 없는 코드 조각은 직접 대응에서 제외한다.
- @login_required, Depends(get_current_user), 인증 middleware 등 상위 진입점에서 인증이 적용된 코드에는 대응하지 않는다.
- 사용자 신원은 확인하지만 역할·권한 검사만 빠진 경우는 CWE-862로 구분한다.
- 다른 사용자의 객체 소유권 검증이 핵심이면 CWE-639로 구분한다.
- 공개 정보나 인증이 필요하지 않은 기능은 제외한다.

[취약 코드 예시]
@app.get("/admin/backup/download")
def download_backup():
    backup_path = "/var/backups/app/database.dump"

    return send_file(
        backup_path,
        as_attachment=True,
    )

[개선 코드 예시]
from flask_login import login_required

@app.get("/admin/backup/download")
@login_required
def download_backup():
    backup_path = "/var/backups/app/database.dump"

    return send_file(
        backup_path,
        as_attachment=True,
    )

[패치 원리]
외부 중요 기능의 진입점에서 서버가 호출자의 신원을 검증해야 한다. 인증 처리는 UI 표시 여부가 아니라 라우트 decorator, dependency 또는 middleware로 강제하고, 필요한 역할 검사는 인증과 별도의 인가 단계에서 수행한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-306: Missing Authentication for Critical Function
- OWASP Authentication Cheat Sheet
''',
    },
    {
        "id": "cwe_306_websocket_admin_command_no_auth",
        "cwe": "CWE-306",
        "document": '''from flask_socketio import SocketIO, emit

socketio = SocketIO()


@socketio.on("admin_command")
def handle_admin_command(message: dict) -> None:
    if message.get("action") == "reload_config":
        reload_runtime_config()
        emit("admin_result", {"ok": True})
''',
        "full_text": '''[취약점 명칭]
외부 WebSocket 관리자 명령 이벤트의 인증 누락

[CWE 번호]
CWE-306

[상세 설명]
외부 클라이언트가 전송할 수 있는 WebSocket 이벤트 핸들러가 연결 사용자나 메시지 발행자의 신원을 확인하지 않고 설정 재로드, 종료, 데이터 Export 같은 중요 명령을 실행하면 익명 연결이 관리자 기능을 호출할 수 있다. 함수 이름이나 message 인자만으로 판단하지 않고, 실제 WebSocket 이벤트 진입점과 중요 동작이 코드에 함께 나타나야 한다.

[탐지 범위]
- @socketio.on, websocket route, WebSocket receive loop처럼 외부 메시지를 받는 진입점이 코드에 명확히 존재하는 경우
- reload, shutdown, reset, export, purge 같은 중요 작업을 메시지 action만으로 실행하는 경우
- 연결 시점 또는 이벤트 처리 시점에 세션, 토큰, 사용자 identity 인증이 확인되지 않는 경우
- 외부 WebSocket 메시지가 중요 기능까지 직접 도달하는 흐름

[잡지 말아야 할 코드]
- 일반 dict 처리 함수나 내부 message helper를 WebSocket 진입점이라고 추정하지 않는다.
- 연결 handshake에서 인증이 강제되고 이벤트 핸들러가 검증된 identity만 받는 흐름이 코드로 확인되면 제외한다.
- 사용자는 인증되었지만 관리자 역할 검사만 누락된 경우는 CWE-862로 구분한다.
- 내부 이벤트 버스이며 외부 사용자가 메시지를 보낼 수 없다는 코드상 보장이 있는 경우는 제외한다.
- 단순 WebSocket Origin 검증 누락은 별도의 Origin 관련 CWE로 구분한다.

[취약 코드 예시]
@socketio.on("admin_command")
def handle_admin_command(message: dict) -> None:
    if message.get("action") == "reload_config":
        reload_runtime_config()
        emit("admin_result", {"ok": True})

[개선 코드 예시]
from flask_login import current_user

@socketio.on("admin_command")
def handle_admin_command(message: dict) -> None:
    if not current_user.is_authenticated:
        raise PermissionError("authentication required")

    if message.get("action") == "reload_config":
        reload_runtime_config()
        emit("admin_result", {"ok": True})

[패치 원리]
HTTP가 아닌 WebSocket 채널도 외부 진입점이다. 연결 또는 이벤트 처리 시 서버가 사용자 identity를 검증하고, 인증되지 않은 연결이 중요 명령 처리 코드에 도달하지 못하도록 차단한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-306: Missing Authentication for Critical Function
- OWASP WebSocket Security Cheat Sheet
''',
    },
    {
        "id": "cwe_306_celery_admin_task_no_auth_context",
        "cwe": "CWE-306",
        "document": '''from celery import Celery
from flask import Flask, jsonify, request

app = Flask(__name__)
celery = Celery(__name__)


@celery.task
def run_admin_task(message: dict) -> None:
    if message.get("task") == "purge_users":
        purge_inactive_users()


@app.post("/api/admin/tasks")
def enqueue_admin_task():
    message = request.get_json()
    run_admin_task.delay(message)

    return jsonify({"queued": True}), 202
''',
        "full_text": '''[취약점 명칭]
인증 없는 HTTP 요청이 비동기 관리자 작업으로 전달됨

[CWE 번호]
CWE-306

[상세 설명]
외부 HTTP 요청이 인증 없이 관리자 작업 메시지를 만들고, 그 메시지가 비동기 worker에서 사용자 삭제·데이터 초기화·내부 Export 같은 중요 기능으로 실행되면 익명 사용자가 작업 큐를 통해 중요 기능을 호출할 수 있다. Celery 함수에 인증 인자가 없다는 사실만으로 판단하지 않고, 외부 입력 진입점에서 비동기 작업까지 연결되는 전체 흐름을 코드로 확인해야 한다.

[탐지 범위]
- 외부 HTTP·RPC·메시지 진입점에서 사용자 입력을 받아 Celery·RQ·worker 작업으로 전달하는 경우
- 해당 작업이 purge, reset, export, rebuild 같은 중요 기능을 수행하는 경우
- 외부 진입점에 로그인·토큰·API Key 인증이 없고 worker에 검증된 actor identity도 전달되지 않는 경우
- 익명 외부 요청이 비동기 경계를 넘어 중요 기능까지 도달하는 흐름이 코드에 명확한 경우

[잡지 말아야 할 코드]
- Celery task 함수만 있고 작업을 누가 발행할 수 있는지 확인되지 않는 경우에는 직접 대응하지 않는다.
- broker ACL, 네트워크 격리 등 인프라 설정만을 근거로 안전하거나 취약하다고 판단하지 않는다.
- 인증된 HTTP 라우트가 검증된 actor identity를 작업 메시지에 포함하고 worker가 이를 재검증하는 코드는 제외한다.
- 단순 내부 예약 작업이나 고정된 시스템 스케줄 작업은 제외한다.
- 메시지 서명·무결성 검증 자체가 핵심이면 CWE-345 등으로 구분한다.

[취약 코드 예시]
@app.post("/api/admin/tasks")
def enqueue_admin_task():
    message = request.get_json()
    run_admin_task.delay(message)

    return jsonify({"queued": True}), 202

[개선 코드 예시]
from flask_login import current_user, login_required

@app.post("/api/admin/tasks")
@login_required
def enqueue_admin_task():
    message = request.get_json()

    run_admin_task.delay({
        "task": message.get("task"),
        "actor_id": current_user.get_id(),
    })

    return jsonify({"queued": True}), 202

[패치 원리]
인증은 비동기 worker 함수의 존재 여부가 아니라 외부 작업 생성 진입점에서 강제해야 한다. 인증된 사용자 identity를 작업 메시지에 안전하게 결합하고, 중요 작업은 worker에서도 신뢰된 actor와 작업 종류를 검증한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-306: Missing Authentication for Critical Function
- OWASP Authentication Cheat Sheet
- Celery Security documentation
''',
    },
    {
        "id": "cwe_312_cleartext_storage_sensitive_config",
        "cwe": "CWE-312",
        "document": '''import json


def save_token(
    user_id: str,
    access_token: str,
) -> None:
    data = {
        "user_id": user_id,
        "access_token": access_token,
    }

    with open(
        "tokens.json",
        "w",
        encoding="utf-8",
    ) as token_file:
        json.dump(data, token_file)
''',
        "full_text": '''[취약점 명칭]
민감 토큰을 영속 파일에 평문 저장

[CWE 번호]
CWE-312

[상세 설명]
비밀번호, 재사용 가능한 인증 토큰, API 키 같은 민감정보를 암호화 또는 적절한 단방향 처리 없이 파일·데이터베이스·공유 저장소에 영속적으로 기록하면 저장 매체를 읽을 수 있는 다른 권한 영역의 행위자가 원문을 획득할 수 있다. 함수 지역 변수나 외부 노출 근거가 없는 단일 프로세스 private 객체에 값이 잠시 존재하는 것만으로는 평문 저장 취약점을 확정하지 않는다.

[탐지 범위]
- open, json.dump, yaml.dump, write 등을 통해 민감정보를 파일·설정·백업에 원문으로 기록하는 경우
- INSERT, UPDATE, repository.save 등으로 토큰·API 키·개인정보를 영속 데이터베이스에 원문 저장하는 흐름이 확인되는 경우
- Redis·Memcached 등 공유 저장소에 민감 원문을 저장하고 다른 보안 주체가 읽을 가능성이 코드로 확인되는 경우
- 로그 파일이나 감사 기록에 재사용 가능한 자격 증명 원문을 기록하는 경우

[잡지 말아야 할 코드]
- 함수 내부 변수, dataclass 필드, 단일 프로세스 private dict에 민감값이 일시적으로 존재한다는 이유만으로 탐지하지 않는다.
- 저장소가 파일·DB·공유 캐시 등 영속 또는 공유 매체라는 근거가 없는 경우는 제외한다.
- 비밀값을 생성해 즉시 호출자에게 반환하는 코드만으로 평문 저장이라고 판단하지 않는다.
- 변수명에 password, token, secret이 있다는 사실만으로 저장 취약점을 확정하지 않는다.
- 비밀번호를 Argon2·bcrypt 등 적절한 password hashing으로 저장하는 코드는 제외한다.
- 토큰을 안전한 KMS·Secret Manager에 보관하거나 애플리케이션 저장소에 강한 암호화로 저장하는 코드는 제외한다.
- 메모리 덤프를 통한 평문 노출이 핵심이면 CWE-316과 별도로 구분한다.

[취약 코드 예시]
with open(
    "tokens.json",
    "w",
    encoding="utf-8",
) as token_file:
    json.dump(
        {
            "user_id": user_id,
            "access_token": access_token,
        },
        token_file,
    )

[개선 코드 예시]
import os
from cryptography.fernet import Fernet

key = os.environ["TOKEN_ENCRYPTION_KEY"].encode()
cipher = Fernet(key)

def save_token(
    user_id: str,
    access_token: str,
    repository,
) -> None:
    encrypted_token = cipher.encrypt(
        access_token.encode("utf-8"),
    ).decode("utf-8")

    repository.save({
        "user_id": user_id,
        "access_token": encrypted_token,
    })

[패치 원리]
민감정보를 저장해야 한다면 데이터 유형에 맞는 보호 방식을 적용한다. 비밀번호는 password hashing을 사용하고, 다시 사용해야 하는 토큰·키는 외부 키 관리와 강한 암호화를 적용한다. 단순 인메모리 보유와 영속·공유 저장을 구분한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-312: Cleartext Storage of Sensitive Information
- OWASP Cryptographic Storage Cheat Sheet
''',
    },
    {
        "id": "snyk_lesson_broken_access_control_missing_authorization",
        "cwe": "CWE-862",
        "document": '''from flask import Flask, jsonify, request

app = Flask(__name__)

grades = {
    "20223948": {
        "student_name": "Ezra",
        "grade": "F",
    },
}


def get_authenticated_user() -> dict | None:
    user_id = request.headers.get("X-User-Id")

    if not user_id:
        return None

    return {
        "user_id": user_id,
        "role": request.headers.get(
            "X-User-Role",
            "student",
        ),
    }


@app.patch("/api/v1/grades/<student_id>")
def update_grade(student_id: str):
    current_user = get_authenticated_user()

    if current_user is None:
        return jsonify({"error": "login required"}), 401

    new_grade = request.json.get("grade")
    grades[student_id]["grade"] = new_grade

    return jsonify(grades[student_id])
''',
        "full_text": '''[취약점 명칭]
인증된 사용자의 역할 기반 권한 검사 누락

[CWE 번호]
CWE-862

[상세 설명]
서버가 호출자의 신원을 확인해 인증된 사용자를 확보했지만, 교사·관리자·운영자처럼 특정 역할만 수행해야 하는 민감 기능을 실행하기 전에 해당 사용자의 역할·권한·scope를 검사하지 않으면 일반 사용자가 제한 기능을 실행할 수 있다. 함수에 current_user가 없다는 사실만으로 판단하지 않고, 인증된 주체와 역할 제한 기능이 코드에 함께 나타나야 한다.

[탐지 범위]
- 세션, JWT, API Key 등으로 인증된 현재 사용자 정보가 코드에 존재하는 경우
- 성적 수정, 권한 변경, 사용자 정지, 관리자 설정 변경처럼 특정 역할에게만 허용되는 기능이 명확한 경우
- 인증 성공 후 role, permission, scope, capability를 확인하지 않고 민감 상태를 변경하는 경우
- 외부 진입점과 분석 가능한 호출 흐름 전체에서 인가 검사가 누락된 사실을 확인할 수 있는 경우

[잡지 말아야 할 코드]
- 일반 service·repository·helper 함수에 current_user 인자가 없다는 이유만으로 인가 누락을 추정하지 않는다.
- 외부 라우트인지 내부 함수인지 알 수 없거나 상위 계층의 권한 검사를 확인할 수 없는 부분 코드에는 직접 대응하지 않는다.
- 사용자 인증 자체가 전혀 없는 중요 기능은 CWE-306으로 구분한다.
- 객체 식별자 조작으로 다른 사용자의 객체에 접근하는 소유권 문제는 CWE-639로 구분한다.
- 인가 검사는 존재하지만 잘못된 역할이나 정책을 허용하는 경우는 CWE-863으로 구분한다.
- 함수 이름이 admin, enroll, delete라는 이유만으로 역할 제한 기능이라고 추정하지 않는다.

[취약 코드 예시]
current_user = get_authenticated_user()

if current_user is None:
    return jsonify({"error": "login required"}), 401

new_grade = request.json.get("grade")
grades[student_id]["grade"] = new_grade

[개선 코드 예시]
current_user = get_authenticated_user()

if current_user is None:
    return jsonify({"error": "login required"}), 401

if current_user.get("role") not in {
    "teacher",
    "admin",
}:
    return jsonify({"error": "forbidden"}), 403

new_grade = request.json.get("grade")
grades[student_id]["grade"] = new_grade

[패치 원리]
인증과 인가를 분리한다. 신원을 확인한 뒤에도 민감 기능마다 서버 측 역할·권한·scope를 검증해야 한다. UI 버튼 숨김이나 함수명은 인가 통제가 아니며, 외부 진입점에서 정책을 강제한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-862: Missing Authorization
- OWASP Authorization Cheat Sheet
''',
    },
    {
        "id": "cwe_837_checkout_without_idempotency_key",
        "cwe": "CWE-837",
        "document": '''def submit_payment(
    user_id: str,
    order_id: str,
    amount: int,
) -> dict:
    charge_id = payment_gateway_charge(
        user_id,
        amount,
    )

    save_payment(
        order_id,
        charge_id,
        amount,
    )

    return {
        "charge_id": charge_id,
    }
''',
        "full_text": '''[취약점 명칭]
외부 결제 요청의 단일 실행 보장 누락

[CWE 번호]
CWE-837

[상세 설명]
결제 승인, 환불, 송금처럼 같은 업무 요청이 정확히 한 번만 실행되어야 하는 기능에서 동일 작업 식별자나 idempotency key를 확인하지 않고 외부 부작용을 먼저 수행하면, 네트워크 재시도나 중복 제출로 금액·재화·권한이 반복 변경될 수 있다. 일반 create·save·overwrite 함수에 멱등성 키가 없다는 사실만으로는 이 취약점을 확정하지 않는다.

[탐지 범위]
- 결제 승인, 환불, 송금, 포인트 차감, 쿠폰 사용처럼 코드상 한 번만 수행되어야 하는 업무 작업
- order_id, payment_id, refund_id처럼 동일 작업을 식별할 수 있는 값이 존재하는 경우
- 이미 처리된 작업인지 확인하기 전에 PG·은행·외부 서비스 호출 또는 비가역적 상태 변경을 수행하는 경우
- 같은 식별자의 요청을 재전송하면 실제 외부 부작용이 반복된다는 흐름을 코드에서 확인할 수 있는 경우

[잡지 말아야 할 코드]
- 일반적인 create, update, save, upsert에 idempotency key가 없다는 이유만으로 탐지하지 않는다.
- 같은 dict 키나 DB 행을 덮어쓴다는 사실만으로 단일 실행 위반이라고 판단하지 않는다.
- 토큰·세션·비밀값 재발급은 반복 실행이 허용될 수 있으므로 금지 정책이 코드에 없으면 제외한다.
- 외부 부작용이나 중복 실행 피해가 확인되지 않는 내부 함수는 제외한다.
- idempotency key를 저장하고 재요청에 기존 결과를 반환하는 코드는 제외한다.
- 주문 상태를 pending·paid 등으로 원자적으로 전이해 중복 결제를 차단하는 코드는 제외한다.
- 단순 상태 전이 순서 문제는 CWE-841로 구분한다.

[취약 코드 예시]
charge_id = payment_gateway_charge(
    user_id,
    amount,
)

save_payment(
    order_id,
    charge_id,
    amount,
)

[개선 코드 예시]
def submit_payment(
    user_id: str,
    order_id: str,
    amount: int,
    idempotency_key: str,
) -> dict:
    existing = find_payment_by_idempotency_key(
        idempotency_key,
    )

    if existing is not None:
        return {
            "charge_id": existing["charge_id"],
        }

    charge_id = payment_gateway_charge(
        user_id,
        amount,
    )

    save_payment(
        order_id,
        charge_id,
        amount,
        idempotency_key,
    )

    return {
        "charge_id": charge_id,
    }

[패치 원리]
정확히 한 번만 수행되어야 하는 외부 부작용은 작업 식별자, idempotency key, 상태 잠금 또는 원자적 중복 검사를 사용해 재실행을 막는다. 멱등성이 필요하다는 업무 조건과 실제 반복 피해가 코드에서 확인되는 경우에만 이 패턴을 적용한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-837: Improper Enforcement of a Single, Unique Action
- OWASP Transaction Authorization Cheat Sheet
''',
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "CWE-306, 312, 862, 837 문서의 탐지 경계를 "
            "긍정 증거 기반으로 수정합니다."
        )
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="실제로 DB를 수정합니다. 없으면 계획만 출력합니다.",
    )
    return parser.parse_args()


def extract_section_text(
    full_text: str,
    section_name: str,
) -> str:
    pattern = (
        rf"\[{re.escape(section_name)}\]\s*"
        rf"(.*?)(?=\n\[[^\]]+\]|\Z)"
    )
    match = re.search(pattern, full_text or "", re.DOTALL)
    return match.group(1).strip() if match else ""


def validate_pattern(pattern: dict) -> None:
    required_sections = [
        "[취약점 명칭]",
        "[CWE 번호]",
        "[상세 설명]",
        "[탐지 범위]",
        "[잡지 말아야 할 코드]",
        "[취약 코드 예시]",
        "[개선 코드 예시]",
        "[패치 원리]",
        "[검증 등급]",
        "[참고 출처]",
    ]

    if not pattern["id"].strip():
        raise ValueError("패턴 ID가 비어 있습니다.")

    if not pattern["cwe"].startswith("CWE-"):
        raise ValueError(
            f"CWE 형식 오류: {pattern['id']} / {pattern['cwe']}"
        )

    if not pattern["document"].strip():
        raise ValueError(
            f"document가 비어 있습니다: {pattern['id']}"
        )

    for section in required_sections:
        if section not in pattern["full_text"]:
            raise ValueError(
                f"{pattern['id']} 필수 섹션 누락: {section}"
            )

    full_text_cwe = extract_section_text(
        pattern["full_text"],
        "CWE 번호",
    ).splitlines()[0].strip()

    if full_text_cwe != pattern["cwe"]:
        raise ValueError(
            "metadata CWE와 full_text CWE 불일치: "
            f"{pattern['id']} / metadata={pattern['cwe']} / "
            f"full_text={full_text_cwe}"
        )


def backup_db(chroma_dir: str) -> Path:
    source = Path(chroma_dir)

    if not source.exists():
        raise FileNotFoundError(
            f"ChromaDB 경로가 존재하지 않습니다: {source.resolve()}"
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = (
        source.parent
        / f"{source.name}_backup_before_refine_306_312_862_837_{timestamp}"
    )

    shutil.copytree(source, backup_path)
    print(f"[백업 완료] {backup_path.resolve()}")
    return backup_path


def open_collection():
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    collection = client.get_collection(COLLECTION_NAME)
    return client, collection


def get_items(collection, ids: list[str]) -> dict[str, dict]:
    if not ids:
        return {}

    result = collection.get(
        ids=ids,
        include=["documents", "metadatas"],
    )

    items: dict[str, dict] = {}

    for index, document_id in enumerate(result["ids"]):
        metadata = result["metadatas"][index] or {}
        items[document_id] = {
            "id": document_id,
            "document": result["documents"][index] or "",
            "cwe": metadata.get("cwe", ""),
            "full_text": metadata.get("full_text", ""),
        }

    return items


def upsert_patterns(collection, patterns: list[dict]) -> None:
    collection.upsert(
        ids=[item["id"] for item in patterns],
        documents=[item["document"] for item in patterns],
        metadatas=[
            {
                "cwe": item["cwe"],
                "full_text": item["full_text"],
            }
            for item in patterns
        ],
    )


def main() -> None:
    args = parse_args()

    for pattern in PATTERNS:
        validate_pattern(pattern)

    target_ids = [item["id"] for item in PATTERNS]
    check_ids = list({
        *target_ids,
        *DELETE_IF_PRESENT.keys(),
    })

    client, collection = open_collection()
    before_count = collection.count()
    current_items = get_items(collection, check_ids)

    print("=== CWE 탐지 경계 수정 계획 ===")
    print(f"컬렉션: {COLLECTION_NAME}")
    print(f"현재 문서 수: {before_count}")

    if before_count != EXPECTED_CURRENT_COUNT:
        print(
            "[주의] 검토 당시 DB 문서 수와 현재 문서 수가 다릅니다. "
            f"검토 기준={EXPECTED_CURRENT_COUNT}, 현재={before_count}"
        )

    missing_ids = [
        document_id
        for document_id in target_ids
        if document_id not in current_items
    ]

    if missing_ids:
        raise ValueError(
            f"수정 대상 문서가 없습니다: {missing_ids}"
        )

    for pattern in PATTERNS:
        old_item = current_items[pattern["id"]]

        if old_item["cwe"] != pattern["cwe"]:
            raise ValueError(
                "수정 대상 CWE가 예상과 다릅니다. "
                f"id={pattern['id']} / "
                f"예상={pattern['cwe']} / 실제={old_item['cwe']}"
            )

    print()
    print("[관리자 지표 문서 처리]")

    old_metrics = current_items.get(
        "cwe_862_admin_metrics_endpoint_without_auth"
    )

    if old_metrics is None:
        print("- 기존 관리자 지표 문서: 이미 없음")
        print("- CWE-306에 새로 추가하지 않음")
    else:
        print("- 기존 관리자 지표 문서: 삭제 예정")
        print("- CWE-306에 새로 추가하지 않음")

    print()
    print("[수정 대상]")

    for pattern in PATTERNS:
        print(
            f"- {pattern['id']} / {pattern['cwe']} / "
            f"{extract_section_text(pattern['full_text'], '취약점 명칭')}"
        )

    delete_ids = []

    for document_id, expected_cwe in DELETE_IF_PRESENT.items():
        item = current_items.get(document_id)

        if item is None:
            continue

        if item["cwe"] != expected_cwe:
            raise ValueError(
                "삭제 대상 CWE가 예상과 다릅니다. "
                f"id={document_id} / "
                f"예상={expected_cwe} / 실제={item['cwe']}"
            )

        delete_ids.append(document_id)

    expected_after_count = before_count - len(delete_ids)

    print()
    print(f"동일 ID 수정: {len(PATTERNS)}개")
    print(f"조건부 삭제: {len(delete_ids)}개")
    print(f"예상 실행 후 문서 수: {expected_after_count}")

    if not args.apply:
        print()
        print("DRY RUN입니다. 실제로 적용하려면:")
        print(
            "python refine_cwe_306_312_862_837.py --apply"
        )
        return

    del collection
    del client
    gc.collect()

    if AUTO_BACKUP:
        backup_db(CHROMA_DIR)

    client, collection = open_collection()

    if delete_ids:
        collection.delete(ids=delete_ids)

    upsert_patterns(collection, PATTERNS)

    after_count = collection.count()
    saved_items = get_items(collection, target_ids)

    for pattern in PATTERNS:
        saved = saved_items.get(pattern["id"])

        if saved is None:
            raise RuntimeError(
                f"수정 문서 저장 실패: {pattern['id']}"
            )

        if saved["cwe"] != pattern["cwe"]:
            raise RuntimeError(
                f"수정 CWE 검증 실패: {pattern['id']}"
            )

        if saved["document"] != pattern["document"]:
            raise RuntimeError(
                f"document 수정 검증 실패: {pattern['id']}"
            )

        if saved["full_text"] != pattern["full_text"]:
            raise RuntimeError(
                f"full_text 수정 검증 실패: {pattern['id']}"
            )

    deleted_remaining = get_items(collection, delete_ids)

    if deleted_remaining:
        raise RuntimeError(
            "삭제 대상 문서가 남아 있습니다: "
            f"{sorted(deleted_remaining)}"
        )

    if after_count != expected_after_count:
        raise RuntimeError(
            "예상 문서 수와 실제 문서 수가 다릅니다. "
            f"예상={expected_after_count}, 실제={after_count}"
        )

    print()
    print("=== CWE 탐지 경계 수정 완료 ===")
    print(f"실행 전 문서 수: {before_count}")
    print(f"실행 후 문서 수: {after_count}")
    print(f"수정 완료: {len(PATTERNS)}개")
    print(f"조건부 삭제 완료: {len(delete_ids)}개")
    print("관리자 지표 문서는 CWE-306에 추가하지 않았습니다.")
    print("모든 document, full_text, CWE 검증을 통과했습니다.")


if __name__ == "__main__":
    main()
