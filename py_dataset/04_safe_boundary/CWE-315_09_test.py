import secrets


def create_checkout_cookie(
    email: str,
    card_token: str,
) -> dict:
    checkout_id = secrets.token_urlsafe(
        24
    )
    checkout_store.save(
        checkout_id,
        {
            "email": email,
            "card_token": card_token,
        },
    )

    return {
        "name": "checkout_id",
        "value": checkout_id,
        "http_only": True,
        "secure": True,
    }
