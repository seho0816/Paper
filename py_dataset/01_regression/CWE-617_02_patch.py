def assign_role(account_id: str, requested_role: str) -> None:
    if requested_role not in {'member', 'auditor'}:
        raise ValueError("Invalid role requested.")
    membership_repository.set_role(account_id, requested_role)
