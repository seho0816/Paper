import bcrypt

# --- 외부 함수 (취약점 수정 대상이 아니지만, 완전한 코드 구성을 위해 포함) ---
# 실제 운영 환경에서는 데이터베이스 또는 안전한 저장소에서 계정 정보를 가져와야 합니다.
# account["mother_maiden_name"] 필드는 bcrypt로 해시된 바이트 문자열을 저장한다고 가정합니다.
def find_account(email: str) -> dict | None:
    # 이메일에 해당하는 계정을 찾아 반환합니다.
    # 예시 데이터 (실제 데이터베이스에서 가져와야 함)
    # "secretanswer" 의 bcrypt 해시 (b'secretanswer' -> b'$2b$12$...' 형태)
    # 실제로는 계정 생성/수정 시 bcrypt.hashpw(b"plaintext_answer", bcrypt.gensalt())로 저장되어야 합니다.
    example_hashed_answer = b'$2b$12$lOQ/u.Y9s8K9p0Z6L5M7w.qR.t2.s.t2.s.t2.s.t2.s.t2.s.' # bcrypt for "secretanswer"
    
    if email == "user@example.com":
        return {
            "id": "12345",
            "email": "user@example.com",
            "mother_maiden_name": example_hashed_answer,
        }
    return None

# 실제 운영 환경에서는 데이터베이스에 새 비밀번호를 안전하게 저장해야 합니다.
# new_password는 이 함수 내에서 적절한 키 스트레칭 해싱 알고리즘(예: bcrypt)으로 해시되어 저장되어야 합니다.
def update_password(account_id: str, new_password: str) -> None:
    # 이 함수는 새로운 비밀번호를 받아, 안전한 해싱을 거쳐 저장한다고 가정합니다.
    # 예를 들어, 내부적으로 bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())를 사용합니다.
    pass

# --- 취약한 코드 수정 부분 ---
def recover_account(
    email: str,
    answer: str,
    new_password: str,
) -> bool:
    account = find_account(
        email,
    )

    if account is None:
        return False

    # CWE-640 (약한 인증) 취약점 수정:
    # 보안 질문의 답을 평문으로 비교하는 대신,
    # 제공된 답을 해시하여 저장된 해시 값과 비교합니다.
    # 이는 DB 유출 시 보안 질문 답이 평문으로 노출되는 것을 방지하여 보안을 강화합니다.
    # bcrypt는 비밀번호와 같은 민감한 정보를 해시하는 데 권장되는 키 스트레칭 알고리즘입니다.
    try:
        # 사용자가 입력한 답변을 소문자로 변환하고 바이트로 인코딩합니다.
        # account["mother_maiden_name"]은 find_account에서 가져온 해시된 바이트 문자열이어야 합니다.
        if not bcrypt.checkpw(answer.lower().encode('utf-8'), account["mother_maiden_name"]):
            return False
    except ValueError:
        # 저장된 해시 값이 유효한 bcrypt 형식이 아니거나, 비교 중 오류가 발생할 경우
        # (예: account["mother_maiden_name"]이 None 또는 잘못된 형식)
        # 인증 실패로 처리하여 정보 노출을 방지합니다.
        return False


    update_password(
        account["id"],
        new_password,
    )
    return True
