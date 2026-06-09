from fastapi import Request


def payment_return_url(
    request: Request,
    order_id: str,
) -> str:
    return (
        str(
            request.base_url
        )
        + "payments/complete?order_id="
        + order_id
    )
