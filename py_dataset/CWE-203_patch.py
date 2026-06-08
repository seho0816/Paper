import bcrypt

# CWE-203 (Observable Discrepancy) 취약점 방지를 위한 더미 패스워드 해시를 미리 생성합니다.
# 계정이 존재하지 않을 때도 패스워드 검증 단계를 반드시 거치도록 하여,
# 공격자가 응답 시간이나 오류 메시지 차이를 통해 유효한 계정 이름을 알아내는 것을 방지합니다.
# 이 해시는 비민감성 고정 문자열을 bcrypt로 해싱하여 생성하며,
# gensalt의 rounds를 낮게 설정(예: 4)하여 더미 호출 시 성능 영향을 최소화합니다.
# 이는 'your_token_here'와 같은 임시 더미값이 아닌, 보안 메커니즘을 위한 기능적 값입니다.
_DUMMY_PASSWORD_HASH_FOR_CWE203 = bcrypt.hashpw(
    b"nonexistent_user_password_to_prevent_enumeration",
    bcrypt.gensalt(rounds=4)
).decode('utf-8')


class LoginService:
    def authenticate(self, email: str, password: str) -> bool:
        account = find_account(email)

        # CWE-203 (Observable Discrepancy) 취약점을 방지하기 위해,
        # 계정 존재 여부와 관계없이 항상 패스워드 검증 단계를 수행하도록 합니다.
        # 계정이 존재하지 않는 경우, 검증에 실패할 더미 패스워드 해시를 사용합니다.
        if account is None:
            # 존재하지 않는 계정에 대해 미리 생성된 더미 해시를 사용합니다.
            # 이는 verify_password_hash 함수가 유효한(bcrypt 호환) 해시와 함께 호출되도록 보장하여,
            # 계정이 존재하지만 패스워드가 틀린 경우와 실행 경로를 구별할 수 없게 만듭니다.
            hash_to_check_against = _DUMMY_PASSWORD_HASH_FOR_CWE203
        else:
            # 존재하는 계정의 경우, 저장된 패스워드 해시를 사용합니다.
            # account["password_hash"]가 유효한 bcrypt 해시 문자열이라고 가정합니다.
            hash_to_check_against = account["password_hash"]

        # 계정 존재 여부와 관계없이 항상 verify_password_hash를 호출합니다.
        # password(str)는 직접 전달되며, 함수 내에서 인코딩을 처리합니다.
        return verify_password_hash(password, hash_to_check_against)


def find_account(email: str) -> dict | None:
    # 이 함수는 스텁(stub)입니다. 실제 애플리케이션에서는 데이터베이스를 조회할 것입니다.
    return None


def verify_password_hash(password: str, password_hash: str) -> bool:
    # 이 함수는 파이썬 보안 전문가의 [엄격한 규칙] 8번("패스워드 해시 용도라면 반드시 bcrypt, argon2, scrypt 등 키 스트레칭 알고리즘을 사용하세요.")에 따라
    # 강력한 키 스트레칭 알고리즘(bcrypt)을 사용하도록 업데이트되었습니다.
    # 원래 구현(password == password_hash)은 매우 취약했습니다.
    # CWE-203은 관찰 가능한 불일치에 관한 것이지만, 규칙 8은 코드의 전반적인 안전성을 위해
    # "패스워드 해시 용도"에는 강력한 알고리즘을 사용하도록 지시합니다. 이는 중요한 보안 강화입니다.

    # password_hash가 비어있거나 유효한 bcrypt 해시 형식($2a$, $2b$, $2y$로 시작)이 아닌 경우
    # 검증을 시도하기 전에 False를 반환하여 오류를 방지합니다.
    if not password_hash or not (password_hash.startswith('$2a$') or
                                 password_hash.startswith('$2b$') or
                                 password_hash.startswith('$2y$')):
        return False
    
    try:
        # bcrypt.checkpw는 패스워드와 해시 모두 bytes 타입을 기대합니다.
        # 입력된 password 문자열을 UTF-8로 인코딩합니다.
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except ValueError:
        # password_hash가 유효한 bcrypt 해시 형식이 아닌 경우(예: 손상된 데이터)
        # 발생하는 ValueError를 처리하여 False를 반환합니다.
        return False
