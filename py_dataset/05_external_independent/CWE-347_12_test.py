from authlib.jose import JsonWebToken


def decode_partner_token(
    token: str,
) -> dict:
    jwt = JsonWebToken(
        ["HS256", "RS256"]
    )

    claims = jwt.decode(
        token,
        key=None,
        claims_cls=None,
    )

    return dict(claims)
