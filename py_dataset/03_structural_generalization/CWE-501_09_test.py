from functools import wraps


def principal_from_payload(handler):
    @wraps(handler)
    def wrapped(payload: dict):
        principal = Principal(
            user_id=payload['user_id'],
            tenant_id=payload['tenant_id'],
            permissions=set(
                payload.get(
                    'permissions',
                    [],
                )
            ),
        )

        with principal_scope(principal):
            return handler(
                payload['command']
            )

    return wrapped


@principal_from_payload
def execute_command(command: dict):
    return command_bus.dispatch(command)
