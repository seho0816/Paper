import os
from authlib.jose import JsonWebToken
from authlib.common.security import load_key


def decode_partner_token(
    token: str,
) -> dict:
    jwt = JsonWebToken(
        ["HS256", "RS256"]
    )

    # CWE-347 (Improper Verification of Signature in a Security Check) 취약점 수정:
    # 기존 코드에서 `key=None`으로 설정되어 있어 JWT 서명 검증이 제대로 이루어지지 않았습니다.
    # 이는 공격자가 임의의 토큰을 생성하여 서명 없이 인증을 우회할 수 있도록 허용합니다.
    # 이 패치에서는 HS256 및 RS256 알고리즘에 대해 환경 변수에서 실제 서명 키를 로드하여 사용합니다.
    # - JWT_HS256_SECRET: HS256 서명 검증을 위한 대칭 비밀 키.
    # - JWT_RS256_PUBLIC_KEY: RS256 서명 검증을 위한 PEM 형식의 공개 키.
    # 환경 변수가 설정되어 있지 않으면 KeyError가 발생하여 보안 구성 누락을 방지합니다.

    # HS256 대칭 비밀 키를 환경 변수에서 가져옵니다.
    hs256_secret_key = os.environ["JWT_HS256_SECRET"]

    # RS256 공개 키(PEM 형식 문자열)를 환경 변수에서 가져와 authlib의 load_key로 파싱합니다.
    rs256_public_key_pem = os.environ["JWT_RS256_PUBLIC_KEY"]
    rs256_public_key = load_key(rs256_public_key_pem)

    # 지원되는 각 알고리즘에 해당하는 키를 딕셔너리 형태로 제공하여 서명 검증에 사용합니다.
    verification_keys = {
        'HS256': hs256_secret_key,
        'RS256': rs256_public_key,
    }

    claims = jwt.decode(
        token,
        key=verification_keys,  # CWE-347 취약점 수정을 위해 유효한 키를 전달합니다.
        claims_cls=None,
    )

    return dict(claims)
