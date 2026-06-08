import jwt


class AccessTokenDecoder:
    def __init__(self, verification_key: str) -> None:
        self.verification_key = verification_key

    def decode(self, encoded_token: str) -> dict:
        # CWE-347 fix: Do not derive the algorithm from the unverified token header.
        # Instead, explicitly specify a list of expected and allowed algorithms.
        # The choice of 'HS256' here is an assumption based on the use of a single
        # 'verification_key', typical for symmetric key algorithms.
        # Replace 'HS256' with the actual algorithms your application expects (e.g., ['RS256'], ['HS256', 'HS384']).
        allowed_algorithms = ["HS256"] 

        return jwt.decode(
            encoded_token,
            self.verification_key,
            algorithms=allowed_algorithms,
        )
