from jwcrypto import jwk, jwt


def verify_identity_token(
    compact_token: str,
    public_jwk: dict,
) -> dict:
    key = jwk.JWK(**public_jwk)
    verified = jwt.JWT(
        key=key,
        jwt=compact_token,
        algs=["RS256", "ES256", "PS256"],
        check_claims={
            "iss": "identity-service",
            "aud": "account-service",
        },
    )

    return parse_claims(
        verified.claims,
    )
