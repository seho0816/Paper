def resolve_check_password(_root, info, email: str, password: str) -> dict:
    valid = info.context.accounts.verify(email, password)
    return {'valid': valid}
