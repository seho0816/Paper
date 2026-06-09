def load_statement(session: dict, statement_id: str) -> dict:
    cache_key = f"{session['account_id']}:{session['session_id']}:{statement_id}"
    statement = statement_cache.get(cache_key)
    if statement is None:
        statement = statement_repository.find(session['account_id'], statement_id)
        if statement is None:
            return {'error': 'not found'}
        statement_cache.set(cache_key, statement)
    if statement['account_id'] != session['account_id']:
        raise PermissionError('owner mismatch')
    return statement

