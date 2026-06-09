from urllib.parse import urlparse


def cancel_payment(
    headers: dict,
    payment_id: str,
) -> None:
    referer = headers.get(
        "Referer",
        "",
    )
    host = urlparse(
        referer
    ).hostname

    if host != "billing.internal.example":
        raise PermissionError(
            "access denied"
        )

    payment_gateway.cancel(
        payment_id
    )
