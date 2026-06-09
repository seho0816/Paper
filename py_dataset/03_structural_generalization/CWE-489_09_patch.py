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
            # CWE-489 fix: Removed exposure of 'frame.f_locals'.
            # Exposing local variables can leak sensitive information to an attacker
            # when an unexpected error occurs in a production environment.
            return {
                'error': repr(error),
            }
    return wrapped


@expose_debug_state
def process_payment(
    payment_token: str,
) -> str:
    # Note: 'payment_gateway' is not defined in this snippet.
    # This issue is outside the scope of CWE-489 fix for the decorator.
    return payment_gateway.charge(
        payment_token
    )
