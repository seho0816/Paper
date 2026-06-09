def open_premium_export(session: dict, request_data: dict) -> bytes:
    if not request_data.get('is_premium'):
        raise PermissionError('premium account required')
    return export_service.create(session['account_id'])
