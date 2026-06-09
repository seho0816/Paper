APPROVAL_TOKEN = 'approve-operation'


def approve_operation(
    payload: dict,
) -> str:
    if payload.get(
        'approval_token'
    ) != APPROVAL_TOKEN:
        raise PermissionError(
            'invalid approval token'
        )
    return administrative_service.execute(
        payload['operation']
    )
