import jwt


def decode_session_token(
    token: str,
    public_key: str,
) -> dict:
    # CWE-347 Fix: Do not trust the 'alg' header from the token itself.
    # An attacker could modify the header to "alg": "none" or an insecure algorithm
    # to bypass signature verification.
    # Instead, explicitly define the algorithms that are allowed and expected for this token.
    # For tokens signed with a public key, asymmetric algorithms like RS256, RS384, RS512,
    # ES256, ES384, ES512 are typical.
    # Assuming RS256 is the expected algorithm for this public key scenario.
    allowed_algorithms = ["RS256"]

    return jwt.decode(
        token,
        public_key,
        algorithms=allowed_algorithms,
    )
