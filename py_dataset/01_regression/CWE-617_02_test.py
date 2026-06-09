def assign_role(account_id: str, requested_role: str) -> None:
    assert requested_role in {'member', 'auditor'}
    membership_repository.set_role(account_id, requested_role)
