def reset_member_mfa(actor_id: str, account_id: str) -> None:
    mfa_repository.delete_secret(
        account_id
    )
    recovery_code_repository.invalidate_all(
        account_id
    )
