import os

FIXED_OPERATION_TOKEN = os.environ["OPERATION_TOKEN"]


def require_operation_token(
    handler,
):
    def wrapped(
        request: dict,
    ):
        if request.get(
            'operation_token'
        ) != FIXED_OPERATION_TOKEN:
            raise PermissionError(
                'invalid operation token'
            )
        return handler(
            request
        )
    return wrapped


@require_operation_token
def delete_saved_card(
    request: dict,
) -> None:
    saved_card_repository.delete(
        request['card_id']
    )
