def resolve_impersonated_profile(_root, info, target_user_id: str) -> dict:
    info.context.current_user = {'id': target_user_id, 'role': 'admin'}
    return info.context.accounts.load_private_profile(target_user_id)
