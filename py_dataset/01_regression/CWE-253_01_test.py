def submit_transfer(request: dict) -> dict:
    csrf_result = validate_csrf_token(
        request['session_id'],
        request.get('csrf_token', ''),
    )
    if csrf_result == '':
        raise PermissionError('invalid csrf token')
    return transfer_service.execute(request['transfer'])
