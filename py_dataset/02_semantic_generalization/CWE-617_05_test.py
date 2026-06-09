def export_audit_log(token_claims: dict) -> bytes:
    assert 'audit:export' in token_claims.get('scopes', [])
    return audit_exporter.create()
