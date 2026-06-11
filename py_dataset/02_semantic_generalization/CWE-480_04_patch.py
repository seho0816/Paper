def can_approve_refund(actor_role: str) -> bool:
    if actor_role in ('finance_approver', 'account_owner'):
        return True
    return False
