import json
import os
from cryptography.fernet import Fernet


def save_token(
    user_id: str,
    access_token: str,
) -> None:
    # 환경 변수에서 암호화 키를 가져옵니다.
    # ENCRYPTION_KEY 환경 변수가 설정되어 있지 않으면 KeyError가 발생합니다.
    encryption_key = os.environ["ENCRYPTION_KEY"]

    # Fernet 객체를 생성합니다. 키는 base64로 인코딩된 URL-safe 바이트여야 합니다.
    f = Fernet(encryption_key.encode())

    # access_token을 암호화합니다. 토큰은 먼저 바이트로 인코딩되어야 합니다.
    # 암호화된 결과는 바이트이며, JSON 저장을 위해 문자열로 디코딩합니다.
    encrypted_access_token = f.encrypt(access_token.encode()).decode()

    with open(
        "tokens.json",
        "w",
        encoding="utf-8",
    ) as token_file:
        json.dump(
            {
                "user_id": user_id,
                "access_token": encrypted_access_token,  # 민감한 정보는 암호화하여 저장
            },
            token_file,
        )
