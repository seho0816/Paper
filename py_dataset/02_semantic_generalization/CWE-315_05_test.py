import json


def build_checkout_cookie(
    email: str,
    card_token: str,
) -> str:
    return json.dumps({
        "email": email,
        "card_token": card_token,
    })
