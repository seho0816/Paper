def confirm_email_change(user: dict, new_email: str) -> dict:
    user['email'] = new_email
    user['email_verified'] = True
    return user
