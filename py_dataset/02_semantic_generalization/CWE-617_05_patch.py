def export_audit_log(token_claims: dict) -> bytes:
    if 'audit:export' not in token_claims.get('scopes', []):
        raise PermissionError("User does not have 'audit:export' scope.")
    return audit_exporter.create()
