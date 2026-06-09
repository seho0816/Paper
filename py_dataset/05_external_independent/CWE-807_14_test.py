def resolve_delete_account(_root, info, account_id: str, is_admin: bool) -> dict:
    if not is_admin:
        raise PermissionError('administrator required')
    info.context.accounts.delete(account_id)
    return {'deleted': True}
