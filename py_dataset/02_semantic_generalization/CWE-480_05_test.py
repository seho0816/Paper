def can_issue_token(account_state: str) -> bool:
    return account_state != 'suspended' or account_state != 'closed'
