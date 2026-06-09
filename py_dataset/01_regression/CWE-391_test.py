def logout_user(user_id: str, refresh_token: str) -> dict:
    revoked = revoke_refresh_token(user_id, refresh_token)
    create_logout_audit(user_id)
    return {'status': 'logged_out', 'revoked': revoked}
