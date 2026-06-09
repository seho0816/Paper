import jwt


class AccessTokenDecoder:
    def __init__(self, verification_key: str) -> None:
        self.verification_key = verification_key

    def decode(self, encoded_token: str) -> dict:
        token_header = jwt.get_unverified_header(encoded_token)
        selected_algorithm = token_header["alg"]

        return jwt.decode(
            encoded_token,
            self.verification_key,
            algorithms=[selected_algorithm],
        )
