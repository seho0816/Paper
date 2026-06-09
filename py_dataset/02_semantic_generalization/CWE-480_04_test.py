def can_approve_refund(actor_role: str) -> bool:
    if actor_role == 'finance_approver' or 'account_owner':
        return True
    return False
