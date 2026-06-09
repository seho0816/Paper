import argparse
import gc
import re
import shutil
from datetime import datetime
from pathlib import Path

import chromadb


CHROMA_DIR = "./rag_db"
COLLECTION_NAME = "python_security_lessons"
EXPECTED_CURRENT_COUNT = 337
AUTO_BACKUP = True

DELETE_ITEMS = {
    "cwe-338-datetime": "CWE-338",
    "cwe_328_md5_token_generation": "CWE-328",
    "snyk_lesson_missing_encryption_base64_token": "CWE-311",
    "cwe_571_always_true_role_condition": "CWE-571",
    "snyk_lesson_broken_function_level_auth": "CWE-285",
    "cwe_862_admin_metrics_endpoint_without_auth": "CWE-862",
    "snyk_lesson_unrestricted_resource_consumption_cwe400": "CWE-400",
    "snyk_lesson_unrestricted_resource_consumption_cwe400_final": "CWE-400",
    "snyk_lesson_insecure_hash_weak_password_hash": "CWE-328",
    "cwe_258_empty_database_password_in_runtime_config": "CWE-258",
    "cwe_1007_unicode_homoglyph_domain_in_payment_review": "CWE-1007",
}

STRICT_DELETE_ITEMS = {
    "cwe_1327_internal_metrics_server_binds_all_interfaces": "CWE-1327",
    "cwe_526_database_password_stored_in_environment": "CWE-526",
}


REPLACEMENT_PATTERNS = [
    {
        "old_id": "cwe_203_login_timing_user_enumeration",
        "old_cwe": "CWE-203",
        "id": "cwe_208_login_timing_user_enumeration",
        "cwe": "CWE-208",
        "document": '''def login(email: str, password: str) -> bool:
    user = find_user_by_email(email)

    if user is None:
        return False

    return verify_password(
        password,
        user["password_hash"],
    )
''',
        "full_text": '''[취약점 명칭]
로그인 처리 시간 차이에 의한 계정 존재 여부 노출

[CWE 번호]
CWE-208

[상세 설명]
존재하지 않는 계정은 즉시 실패시키고 존재하는 계정에만 비용이 큰 비밀번호 해시 검증을 수행하면, 공격자가 반복 측정한 응답 시간 차이로 계정 존재 여부를 추정할 수 있다. 핵심은 오류 메시지 자체가 아니라 입력 상태에 따라 실행되는 작업량과 처리 시간이 관찰 가능하게 달라지는 것이다.

[탐지 범위]
- 로그인 함수에서 사용자를 찾지 못하면 즉시 반환하고, 존재할 때만 Argon2·bcrypt·PBKDF2 같은 고비용 검증을 수행하는 경우
- 비밀값이나 인증값 비교 중 첫 불일치에서 즉시 반환하여 비교 시간이 입력에 따라 달라지는 경우
- 외부 요청자가 같은 연산을 반복해 통계적으로 시간 차이를 관찰할 수 있는 코드

[잡지 말아야 할 코드]
- 존재하지 않는 계정에도 더미 비밀번호 해시 검증을 수행하는 코드는 제외한다.
- 단순히 오류 메시지나 HTTP 상태가 다른 문제만 핵심이면 CWE-203 또는 관련 정보 노출 항목으로 구분한다.
- 네트워크 지연 가능성만 있고 코드상 분기별 작업량 차이가 확인되지 않는 경우는 직접 대응으로 판단하지 않는다.
- 공개 데이터 조회 성능 차이처럼 보안상 비밀 상태를 드러내지 않는 코드는 제외한다.

[취약 코드 예시]
user = find_user_by_email(email)

if user is None:
    return False

return verify_password(
    password,
    user["password_hash"],
)

[개선 코드 예시]
DUMMY_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy"

def login(email: str, password: str) -> bool:
    user = find_user_by_email(email)
    password_hash = (
        user["password_hash"]
        if user is not None
        else DUMMY_PASSWORD_HASH
    )

    password_ok = verify_password(
        password,
        password_hash,
    )

    return user is not None and password_ok

[패치 원리]
비밀 상태에 따라 수행되는 주요 연산과 응답 형식을 가능한 한 균일하게 유지한다. 계정이 존재하지 않는 경우에도 실제 비밀번호 해시와 비슷한 비용의 더미 검증을 수행하고, 인증 결과 비교에는 적절한 상수 시간 비교 함수를 사용한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-208: Observable Timing Discrepancy
- OWASP Authentication Cheat Sheet
''',
    },
    {
        "old_id": "snyk_lesson_memory_leaks_unbounded_cache",
        "old_cwe": "CWE-401",
        "id": "cwe_770_unbounded_user_keyed_cache_growth",
        "cwe": "CWE-770",
        "document": '''from flask import Flask, jsonify, request

app = Flask(__name__)
users_cache: dict[str, dict] = {}


def fetch_user_from_database(user_id: str) -> dict:
    return {
        "id": user_id,
        "name": f"user_{user_id}",
        "profile_image": "large_profile_image_data",
    }


@app.get("/api/v1/user/<user_id>")
def get_user_profile(user_id: str):
    current_user_id = request.headers.get("X-User-Id")

    if user_id not in users_cache:
        users_cache[user_id] = fetch_user_from_database(
            user_id,
        )

    if current_user_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(users_cache[user_id])
''',
        "full_text": '''[취약점 명칭]
사용자 제어 키로 무제한 증가하는 전역 캐시

[CWE 번호]
CWE-770

[상세 설명]
외부 사용자가 다양한 키를 반복해서 요청할 수 있는 경로에서 전역 딕셔너리나 캐시에 항목을 계속 추가하면서 최대 크기, 만료 시간, 제거 정책을 두지 않으면 공격자가 저장 항목 수와 메모리 사용량을 무제한으로 증가시킬 수 있다. 메모리가 더 이상 필요하지 않은데 해제하지 않는 전통적인 누수보다, 공격자가 리소스 할당량을 계속 늘릴 수 있도록 상한을 두지 않은 것이 핵심이다.

[탐지 범위]
- URL·쿼리·요청 본문의 사용자 제어 ID가 전역 dict, list, cache의 새 키나 항목으로 사용되는 경우
- 캐시에 max size, TTL, eviction, 명시적 삭제 정책이 없는 경우
- 권한 확인보다 먼저 비싼 데이터를 읽어 캐시에 추가하여 비인가 요청도 자원 할당을 유발하는 경우
- 반복 요청으로 서로 다른 키를 계속 생성할 수 있는 코드 흐름

[잡지 말아야 할 코드]
- 단일 요청의 숫자 입력이 range나 버퍼 크기를 직접 결정하는 패턴은 별도의 CWE-770 수치 할당 문서로 구분한다.
- 최대 크기가 지정된 LRU/LFU 캐시나 TTL·eviction이 명확히 적용된 코드는 제외한다.
- 고정된 작은 키 집합만 저장하고 증가 가능성이 없는 캐시는 제외한다.
- 객체의 유효 수명이 끝났는데 참조 해제를 놓친 전통적인 메모리 누수는 CWE-401로 구분한다.

[취약 코드 예시]
if user_id not in users_cache:
    users_cache[user_id] = fetch_user_from_database(
        user_id,
    )

[개선 코드 예시]
from functools import lru_cache

@lru_cache(maxsize=100)
def fetch_user_from_database(user_id: str) -> dict:
    return {
        "id": user_id,
        "name": f"user_{user_id}",
    }

@app.get("/api/v1/user/<user_id>")
def get_user_profile(user_id: str):
    current_user_id = request.headers.get("X-User-Id")

    if current_user_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(fetch_user_from_database(user_id))

[패치 원리]
외부 요청으로 증가하는 캐시에는 서버 측 최대 항목 수, TTL, 제거 정책을 적용한다. 권한 검사를 자원 조회와 캐싱보다 먼저 수행하고, 공격자가 임의의 새 키를 계속 생성하지 못하도록 요청과 저장량을 제한한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-770: Allocation of Resources Without Limits or Throttling
- Python functools.lru_cache documentation
- OWASP Denial of Service guidance
''',
    },
    {
        "old_id": "cwe_400_zip_extract_without_limits",
        "old_cwe": "CWE-400",
        "id": "cwe_409_zip_archive_extract_without_output_limits",
        "cwe": "CWE-409",
        "document": '''import zipfile
from pathlib import Path

EXTRACT_ROOT = Path("/tmp/extracted")


def extract_uploaded_archive(archive_path: Path) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(EXTRACT_ROOT)
''',
        "full_text": '''[취약점 명칭]
ZIP 아카이브를 해제 크기 제한 없이 전체 추출

[CWE 번호]
CWE-409

[상세 설명]
압축 입력은 작더라도 해제된 데이터의 전체 크기와 파일 수가 매우 클 수 있다. 외부에서 받은 ZIP 아카이브를 엔트리 수, 개별 파일 크기, 전체 비압축 크기, 압축률 제한 없이 한 번에 추출하면 압축 폭탄으로 CPU·메모리·디스크 자원이 고갈될 수 있다.

[탐지 범위]
- 외부 업로드나 메시지에서 받은 zip·tar 계열 아카이브를 extractall 또는 반복 extract로 즉시 해제하는 경우
- infolist 또는 멤버 메타데이터를 읽어 전체 비압축 크기와 파일 수를 검사하지 않는 경우
- 압축 입력 크기만 제한하고 해제 결과 크기나 비정상적인 압축률을 제한하지 않는 경우
- 해제 작업을 요청 처리 경로에서 시간·용량 제한 없이 수행하는 경우

[잡지 말아야 할 코드]
- 압축 내부 경로가 저장 루트를 이탈하는 Zip Slip 문제는 CWE-22로 구분한다.
- 압축되지 않은 일반 업로드 파일 크기 제한 누락은 CWE-770으로 구분한다.
- 파일 수와 전체 비압축 크기, 개별 크기, 압축률을 사전 검증하고 한도 초과 시 중단하는 코드는 제외한다.
- 신뢰된 내부 아카이브이며 크기 한도가 다른 계층에서 명시적으로 강제되는 경우는 직접 대응으로 판단하지 않는다.

[취약 코드 예시]
with zipfile.ZipFile(archive_path) as archive:
    archive.extractall(EXTRACT_ROOT)

[개선 코드 예시]
import zipfile
from pathlib import Path

MAX_FILES = 100
MAX_TOTAL_SIZE = 20 * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 5 * 1024 * 1024

def extract_uploaded_archive(
    archive_path: Path,
    extract_root: Path,
) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()

        if len(members) > MAX_FILES:
            raise ValueError("too many archive entries")

        total_size = 0

        for member in members:
            if member.file_size > MAX_SINGLE_FILE_SIZE:
                raise ValueError("archive entry is too large")

            total_size += member.file_size

            if total_size > MAX_TOTAL_SIZE:
                raise ValueError("expanded archive is too large")

        archive.extractall(extract_root)

[패치 원리]
압축 데이터는 압축된 입력 크기가 아니라 해제 결과의 총량을 기준으로 제한한다. 추출 전에 엔트리 수, 개별·전체 비압축 크기, 압축률과 경로를 검증하고 한도를 넘으면 작업을 시작하지 않는다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-409: Improper Handling of Highly Compressed Data
- Python zipfile documentation
- OWASP File Upload Cheat Sheet
''',
    },
    {
        "old_id": "cwe_400_large_json_without_size_limit",
        "old_cwe": "CWE-400",
        "id": "cwe_770_large_json_without_size_or_item_limit",
        "cwe": "CWE-770",
        "document": '''import json

from flask import request


def import_items():
    raw_body = request.get_data()
    items = json.loads(raw_body)

    for item in items:
        process_item(item)

    return "imported"
''',
        "full_text": '''[취약점 명칭]
요청 본문과 항목 수 제한 없는 대용량 JSON 처리

[CWE 번호]
CWE-770

[상세 설명]
외부 요청 본문을 크기 제한 없이 메모리에 모두 읽고, 배열 항목 수도 제한하지 않은 채 전체 파싱과 반복 처리를 수행하면 공격자가 큰 입력을 보내 메모리와 CPU 사용량을 과도하게 증가시킬 수 있다. 사용자 입력에 의해 할당되고 처리되는 자원량에 서버 측 상한이 없는 것이 핵심이다.

[탐지 범위]
- request.get_data, request.data, stream.read 등을 명시적 최대 크기 없이 전체 읽기하는 경우
- json.loads 결과가 큰 리스트일 수 있는데 항목 수와 개별 항목 크기를 검사하지 않는 경우
- 파싱한 전체 데이터를 리스트·딕셔너리로 메모리에 유지한 채 동기 반복 처리하는 경우
- 프레임워크 요청 크기 제한과 애플리케이션 항목 수 제한이 모두 확인되지 않는 경우

[잡지 말아야 할 코드]
- 요청 본문 최대 크기와 배열 항목 수를 코드에서 검증하는 경우는 제외한다.
- 제한된 크기의 스트리밍 파서나 배치·큐 기반 처리로 자원 상한을 강제하는 코드는 제외한다.
- JSON 문법 오류 처리 누락만 있는 경우는 이 패턴으로 판단하지 않는다.
- 높은 압축률의 gzip·ZIP 해제 문제는 CWE-409로 구분한다.

[취약 코드 예시]
raw_body = request.get_data()
items = json.loads(raw_body)

for item in items:
    process_item(item)

[개선 코드 예시]
import json

MAX_BODY_SIZE = 1 * 1024 * 1024
MAX_ITEMS = 1000

def import_items():
    raw_body = request.get_data(
        cache=False,
        as_text=False,
    )

    if len(raw_body) > MAX_BODY_SIZE:
        raise ValueError("request body is too large")

    items = json.loads(raw_body)

    if not isinstance(items, list):
        raise ValueError("items must be a list")

    if len(items) > MAX_ITEMS:
        raise ValueError("too many items")

    for item in items:
        process_item(item)

    return "imported"

[패치 원리]
외부 입력이 결정하는 메모리 할당량과 반복 처리량에 서버 측 최대값을 적용한다. 요청 본문 크기, 배열 항목 수, 개별 항목 크기와 처리 시간을 제한하고 대량 작업은 스트리밍 또는 비동기 배치로 분리한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-770: Allocation of Resources Without Limits or Throttling
- Flask request data documentation
- OWASP Denial of Service guidance
''',
    },
]


IN_PLACE_UPDATES = [
    {
        "id": "cwe_524_shared_cache_stores_reset_token",
        "cwe": "CWE-524",
        "document": '''def store_reset_token(
    shared_cache,
    user_id: str,
    email: str,
    reset_token: str,
) -> None:
    shared_cache.set(
        f"password-reset:{user_id}",
        {
            "email": email,
            "reset_token": reset_token,
        },
        ttl_seconds=900,
    )
''',
        "full_text": '''[취약점 명칭]
공유 캐시에 비밀번호 재설정 토큰 평문 저장

[CWE 번호]
CWE-524

[상세 설명]
여러 프로세스·사용자·테넌트가 접근하거나 운영·디버그 기능을 통해 조회될 수 있는 공유 캐시에 비밀번호 재설정 토큰 같은 민감정보를 평문으로 저장하면, 캐시 열람 권한을 획득한 행위자나 잘못된 캐시 노출 경로를 통해 토큰이 유출될 수 있다. 단순한 함수 내부 변수나 외부 노출 근거가 없는 private 딕셔너리 저장만으로는 이 취약점을 확정하지 않는다.

[탐지 범위]
- Redis, Memcached, shared_cache, framework cache처럼 공유 사용이 코드에서 드러나는 저장소에 민감 토큰을 평문으로 저장하는 경우
- 사용자 응답 캐시·디버그 캐시 조회·관리자 cache dump처럼 저장값을 다른 보안 주체가 읽을 수 있는 경로가 함께 존재하는 경우
- 캐시 키만 알면 다른 사용자나 테넌트의 민감 값을 조회할 수 있는 경우
- 비밀번호 재설정 토큰, 세션 자격 증명, API 비밀값의 원문을 캐시에 직접 저장하는 경우

[잡지 말아야 할 코드]
- 클래스 내부 private dict에 값을 저장했다는 사실만으로 공유 캐시라고 추정하지 않는다.
- 코드에 외부·다중 사용자 접근 경로가 없고 단일 프로세스 내부에서만 사용하는 임시 저장소는 직접 대응에서 제외한다.
- 원문 토큰 대신 단방향 해시만 저장하고 접근 통제가 적용된 저장소는 제외한다.
- 데이터베이스에 민감정보를 평문 저장하는 일반 문제는 실제 저장 방식에 따라 CWE-312 등으로 구분한다.

[취약 코드 예시]
shared_cache.set(
    f"password-reset:{user_id}",
    {
        "email": email,
        "reset_token": reset_token,
    },
    ttl_seconds=900,
)

[개선 코드 예시]
import hashlib

def hash_reset_token(reset_token: str) -> str:
    return hashlib.sha256(
        reset_token.encode("utf-8"),
    ).hexdigest()

def store_reset_token(
    shared_cache,
    user_id: str,
    reset_token: str,
) -> None:
    shared_cache.set(
        f"password-reset:{user_id}",
        {
            "token_hash": hash_reset_token(reset_token),
        },
        ttl_seconds=900,
    )

[패치 원리]
공유 캐시에는 민감 토큰 원문을 저장하지 않는다. 서버가 검증할 수 있는 단방향 해시만 저장하고, 키 namespace와 접근 권한, 짧은 TTL, 삭제 정책을 함께 적용한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-524: Use of Cache Containing Sensitive Information
- OWASP Forgot Password Cheat Sheet
''',
    },
    {
        "id": "cwe_294_reusable_otp_not_invalidated",
        "cwe": "CWE-294",
        "document": '''otp_store = {
    "user-100": "123456",
}


def verify_otp(user_id: str, code: str) -> bool:
    expected = otp_store.get(user_id)

    if expected != code:
        return False

    return True
''',
        "full_text": '''[취약점 명칭]
일회용 인증 코드 검증 성공 후 무효화 누락

[CWE 번호]
CWE-294

[상세 설명]
OTP, 이메일 인증코드, 비밀번호 재설정 코드처럼 한 번만 사용되어야 하는 인증 값을 검증한 뒤 삭제하거나 사용 완료 상태로 변경하지 않으면, 공격자가 획득한 값을 다시 전송해 인증 절차를 반복 통과할 수 있다. 발급 코드만 있고 검증·소비 로직이 보이지 않는 경우에는 무효화 누락을 추정하지 않는다.

[탐지 범위]
- 동일 함수 또는 분석 가능한 호출 흐름에서 코드를 조회하고 일치 여부를 검증한 뒤 성공 반환하지만 삭제·used 갱신을 하지 않는 경우
- 검증 성공 이후에도 같은 저장 키와 값이 그대로 남아 두 번째 검증 요청이 성공할 수 있는 경우
- nonce, challenge, reset token의 소비 처리 없이 인증 또는 상태 변경을 완료하는 경우
- 코드상 재사용 가능성이 직접 확인되는 verify·consume 경로

[잡지 말아야 할 코드]
- 인증 코드 발급·저장 함수만 있고 검증 함수가 분석 범위에 없는 경우에는 직접 대응으로 판단하지 않는다.
- 검증 성공 직후 코드 삭제, pop, used=True 갱신 또는 원자적 compare-and-delete를 수행하는 코드는 제외한다.
- 세션 토큰이나 API 키처럼 원래 반복 사용하도록 설계된 자격 증명은 제외한다.
- 단순히 TTL이 길다는 사실만으로 캡처-재전송 취약점을 확정하지 않는다.

[취약 코드 예시]
expected = otp_store.get(user_id)

if expected != code:
    return False

return True

[개선 코드 예시]
otp_store = {
    "user-100": "123456",
}

def verify_otp(user_id: str, code: str) -> bool:
    expected = otp_store.get(user_id)

    if expected != code:
        return False

    del otp_store[user_id]
    return True

[패치 원리]
일회용 인증값은 검증 성공과 소비 처리를 하나의 원자적 작업으로 수행한다. 성공한 값은 즉시 삭제하거나 사용 완료 상태로 변경하고, 짧은 만료 시간과 시도 횟수 제한을 함께 적용한다.

[검증 등급]
A

[참고 출처]
- MITRE CWE-294: Authentication Bypass by Capture-replay
- OWASP Multifactor Authentication Cheat Sheet
- OWASP Forgot Password Cheat Sheet
''',
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "CWE RAG DB의 잘못된 문서를 삭제하고 "
            "인접 CWE 충돌 문서를 재분류·수정합니다."
        )
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="실제로 DB를 수정합니다. 없으면 계획만 출력합니다.",
    )
    parser.add_argument(
        "--strict-code-only",
        action="store_true",
        help=(
            "환경 의존성이 있는 CWE-1327, CWE-526 문서도 "
            "추가 삭제합니다. 적용 후 예상 문서 수는 324개입니다."
        ),
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
    match = re.search(
        pattern,
        full_text or "",
        re.DOTALL,
    )
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


def backup_db(chroma_dir: str) -> Path | None:
    source = Path(chroma_dir)

    if not source.exists():
        raise FileNotFoundError(
            f"ChromaDB 경로가 존재하지 않습니다: {source.resolve()}"
        )

    if not AUTO_BACKUP:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = (
        source.parent
        / f"{source.name}_backup_before_cwe_audit_cleanup_{timestamp}"
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


def verify_expected_cwe(
    item: dict,
    expected_cwe: str,
) -> None:
    if item["cwe"] != expected_cwe:
        raise ValueError(
            "대상 문서 CWE가 예상과 다릅니다. "
            f"id={item['id']} / "
            f"예상={expected_cwe} / 실제={item['cwe']}"
        )


def upsert_patterns(
    collection,
    patterns: list[dict],
) -> None:
    if not patterns:
        return

    collection.upsert(
        ids=[
            pattern["id"]
            for pattern in patterns
        ],
        documents=[
            pattern["document"]
            for pattern in patterns
        ],
        metadatas=[
            {
                "cwe": pattern["cwe"],
                "full_text": pattern["full_text"],
            }
            for pattern in patterns
        ],
    )


def main() -> None:
    args = parse_args()

    for replacement in REPLACEMENT_PATTERNS:
        validate_pattern(replacement)

    for update in IN_PLACE_UPDATES:
        validate_pattern(update)

    delete_items = dict(DELETE_ITEMS)

    if args.strict_code_only:
        delete_items.update(STRICT_DELETE_ITEMS)

    replacement_old_ids = [
        item["old_id"]
        for item in REPLACEMENT_PATTERNS
    ]
    replacement_new_ids = [
        item["id"]
        for item in REPLACEMENT_PATTERNS
    ]
    in_place_ids = [
        item["id"]
        for item in IN_PLACE_UPDATES
    ]

    inspected_ids = list({
        *delete_items.keys(),
        *replacement_old_ids,
        *replacement_new_ids,
        *in_place_ids,
    })

    client, collection = open_collection()
    before_count = collection.count()
    current_items = get_items(
        collection,
        inspected_ids,
    )

    print("=== CWE DB 정리 계획 ===")
    print(f"컬렉션: {COLLECTION_NAME}")
    print(f"현재 문서 수: {before_count}")

    if before_count != EXPECTED_CURRENT_COUNT:
        print(
            "[주의] 검토 당시 문서 수와 현재 문서 수가 다릅니다. "
            f"검토 기준={EXPECTED_CURRENT_COUNT}, 현재={before_count}"
        )

    print()
    print("[삭제 대상]")

    existing_direct_delete_ids: list[str] = []

    for document_id, expected_cwe in delete_items.items():
        item = current_items.get(document_id)

        if item is None:
            print(f"- 이미 없음: {document_id}")
            continue

        verify_expected_cwe(item, expected_cwe)
        existing_direct_delete_ids.append(document_id)
        print(
            f"- {document_id} / {item['cwe']} / "
            f"{extract_section_text(item['full_text'], '취약점 명칭')}"
        )

    print()
    print("[재분류·교체 대상]")

    old_replacement_ids_to_delete: list[str] = []
    new_replacement_ids_already_exist: list[str] = []

    for replacement in REPLACEMENT_PATTERNS:
        old_item = current_items.get(replacement["old_id"])
        new_item = current_items.get(replacement["id"])

        if old_item is not None:
            verify_expected_cwe(
                old_item,
                replacement["old_cwe"],
            )
            old_replacement_ids_to_delete.append(
                replacement["old_id"]
            )

        if new_item is not None:
            new_replacement_ids_already_exist.append(
                replacement["id"]
            )

        print(
            f"- {replacement['old_id']} ({replacement['old_cwe']}) "
            f"→ {replacement['id']} ({replacement['cwe']})"
        )

    print()
    print("[동일 ID 내용 수정 대상]")

    for update in IN_PLACE_UPDATES:
        item = current_items.get(update["id"])

        if item is None:
            raise ValueError(
                f"수정 대상 문서가 없습니다: {update['id']}"
            )

        verify_expected_cwe(item, update["cwe"])
        print(
            f"- {update['id']} / {update['cwe']}"
        )

    calculated_after_count = (
        before_count
        - len(existing_direct_delete_ids)
        - len(old_replacement_ids_to_delete)
        + sum(
            1
            for replacement in REPLACEMENT_PATTERNS
            if replacement["id"]
            not in new_replacement_ids_already_exist
        )
    )

    print()
    print(f"예상 삭제 수: {len(existing_direct_delete_ids)}")
    print(
        "예상 재분류 수: "
        f"{len(REPLACEMENT_PATTERNS)}개 "
        "(기존 삭제 후 새 문서 추가, 총 개수 변화 없음)"
    )
    print(
        f"예상 동일 ID 수정 수: {len(IN_PLACE_UPDATES)}"
    )
    print(f"예상 실행 후 문서 수: {calculated_after_count}")

    if not args.apply:
        print()
        print(
            "DRY RUN입니다. 실제 수정하려면 다음과 같이 실행하세요:"
        )
        print("python cleanup_and_fix_cwe_db.py --apply")

        if not args.strict_code_only:
            print(
                "환경 의존 문서 2개까지 제거하려면:"
            )
            print(
                "python cleanup_and_fix_cwe_db.py "
                "--apply --strict-code-only"
            )

        return

    del collection
    del client
    gc.collect()

    backup_db(CHROMA_DIR)

    client, collection = open_collection()

    if existing_direct_delete_ids:
        collection.delete(
            ids=existing_direct_delete_ids,
        )

    if old_replacement_ids_to_delete:
        collection.delete(
            ids=old_replacement_ids_to_delete,
        )

    replacement_payloads = [
        {
            "id": item["id"],
            "cwe": item["cwe"],
            "document": item["document"],
            "full_text": item["full_text"],
        }
        for item in REPLACEMENT_PATTERNS
    ]

    upsert_patterns(
        collection,
        replacement_payloads,
    )
    upsert_patterns(
        collection,
        IN_PLACE_UPDATES,
    )

    after_count = collection.count()

    all_deleted_ids = [
        *existing_direct_delete_ids,
        *old_replacement_ids_to_delete,
    ]
    deleted_remaining = get_items(
        collection,
        all_deleted_ids,
    )

    if deleted_remaining:
        raise RuntimeError(
            "삭제 후에도 남아 있는 ID가 있습니다: "
            f"{sorted(deleted_remaining)}"
        )

    final_new_items = get_items(
        collection,
        [
            *replacement_new_ids,
            *in_place_ids,
        ],
    )

    for replacement in REPLACEMENT_PATTERNS:
        saved = final_new_items.get(
            replacement["id"]
        )

        if saved is None:
            raise RuntimeError(
                f"재분류 문서가 저장되지 않았습니다: "
                f"{replacement['id']}"
            )

        if saved["cwe"] != replacement["cwe"]:
            raise RuntimeError(
                f"재분류 CWE 검증 실패: {replacement['id']}"
            )

    for update in IN_PLACE_UPDATES:
        saved = final_new_items.get(update["id"])

        if saved is None:
            raise RuntimeError(
                f"수정 문서가 저장되지 않았습니다: "
                f"{update['id']}"
            )

        if saved["cwe"] != update["cwe"]:
            raise RuntimeError(
                f"수정 CWE 검증 실패: {update['id']}"
            )

        if saved["full_text"] != update["full_text"]:
            raise RuntimeError(
                f"full_text 수정 검증 실패: {update['id']}"
            )

    if after_count != calculated_after_count:
        raise RuntimeError(
            "예상 문서 수와 실제 문서 수가 다릅니다. "
            f"예상={calculated_after_count}, 실제={after_count}"
        )

    print()
    print("=== CWE DB 정리 완료 ===")
    print(f"실행 전 문서 수: {before_count}")
    print(f"실행 후 문서 수: {after_count}")
    print(
        f"직접 삭제: {len(existing_direct_delete_ids)}개"
    )
    print(
        f"재분류·교체: {len(REPLACEMENT_PATTERNS)}개"
    )
    print(
        f"동일 ID 내용 수정: {len(IN_PLACE_UPDATES)}개"
    )

    if args.strict_code_only:
        print(
            "엄격한 코드 단독 판별 기준을 적용했습니다."
        )
    else:
        print(
            "CWE-1327과 CWE-526은 유지했습니다."
        )

    print("삭제·재분류·수정 후 검증을 모두 통과했습니다.")


if __name__ == "__main__":
    main()
