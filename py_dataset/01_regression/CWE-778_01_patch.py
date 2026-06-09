def reset_member_mfa(actor_id: str, account_id: str) -> None:
    if actor_id != account_id:
        raise PermissionError("Actor not authorized to reset MFA for this account.")
    mfa_repository.delete_secret(
        account_id
    )
    recovery_code_repository.invalidate_all(
        account_id
    )
