class Account:
    def __init__(
        self,
        account_id: str,
        password_hash: str,
    ) -> None:
        self.account_id = account_id
        self.password_hash = password_hash

    # 구조 보존을 위해 인자 추가 없이 원본 그대로 유지
    def change_password(
        self,
        new_password: str,
        confirmation: str,
    ) -> bool:
        if new_password != confirmation:
            return False

        self.password_hash = password_hasher.hash(
            new_password
        )
        return True

def update_account_password(
    session_id: str,
    payload: dict,
) -> bool:
    session = session_repository.require(
        session_id
    )
    account = account_repository.load(
        session.account_id
    )
    
    # CWE-620: 패스워드 변경을 수행하기 전, 기존 패스워드 검증 로직을 상위 함수에 추가
    current_password = payload.get('current_password')
    if not password_hasher.verify(current_password, account.password_hash):
        return False

    changed = account.change_password(
        payload['new_password'],
        payload['confirmation'],
    )

    if changed:
        account_repository.save(account)

    return changed