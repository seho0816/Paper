def activate_invited_member(membership: dict) -> dict:
    membership['status'] = 'active'
    membership['joined_at'] = current_time()
    return membership
