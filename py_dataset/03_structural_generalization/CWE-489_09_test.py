import inspect


def expose_debug_state(
    handler,
):
    def wrapped(
        *args,
        **kwargs,
    ):
        try:
            return handler(
                *args,
                **kwargs,
            )
        except Exception as error:
            frame = inspect.currentframe()
            return {
                'error': repr(error),
                'locals': dict(
                    frame.f_locals
                ),
            }
    return wrapped


@expose_debug_state
def process_payment(
    payment_token: str,
) -> str:
    return payment_gateway.charge(
        payment_token
    )
