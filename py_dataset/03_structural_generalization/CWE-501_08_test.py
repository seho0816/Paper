from contextvars import ContextVar


current_principal: ContextVar[dict] = ContextVar(
    'current_principal'
)


def consume_job(message: dict) -> None:
    token = current_principal.set({
        'account_id': message['account_id'],
        'role': message.get(
            'role',
            'worker',
        ),
        'organization_id': message[
            'organization_id'
        ],
    })

    try:
        execute_background_operation(
            message['operation'],
            message.get(
                'arguments',
                {},
            ),
        )
    finally:
        current_principal.reset(token)
