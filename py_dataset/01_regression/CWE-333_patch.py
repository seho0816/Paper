import os
import secrets


def create_anonymous_session_id() -> str:
    # CWE-333 fix: 암호학적으로 안전한 난수 생성기 사용
    # random 모듈 대신 os.urandom 기반 secrets 모듈 사용
    # secrets.token_hex는 내부적으로 os.urandom을 사용하여 예측 불가능한 토큰 생성
    random_bytes = os.urandom(32)
    return random_bytes.hex()