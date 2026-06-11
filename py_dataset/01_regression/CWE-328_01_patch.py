import hashlib
import hmac
import os

def create_token(
    user_id: str,
) -> str:
    # CWE-328: 단순 SHA-256 대신 강력한 암호학적 Salt가 적용된 HMAC 사용
    secret_salt = os.environ.get("TOKEN_SECRET_SALT", "fallback_secure_salt").encode('utf-8')
    
    return hmac.new(
        secret_salt,
        user_id.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()