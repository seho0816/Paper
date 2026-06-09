def export_audit_log(token_claims: dict) -> bytes:
    scopes = token_claims.get('scopes', [])
    if 'audit:export' not in scopes:
        raise PermissionError('audit export permission required')
    return audit_exporter.create()

