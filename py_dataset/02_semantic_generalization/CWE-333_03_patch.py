import os
import secrets

def issue_invitation_token(
    email: str,
) -> str:
    # CWE-333: 암호학적으로 안전한 난수 생성기 사용
    token = secrets.token_hex(64)
    
    invitation_repository.save(
        email,
        token,
    )
    return token