import os
import bcrypt


class AuthenticationConfiguration:
    def __init__(
        self,
        required: bool,
    ) -> None:
        self.required = required

    @classmethod
    def load(cls):
        raw = os.getenv(
            'REQUIRE_INTERNAL_AUTH',
            'off',
        )

        return cls(
            required=(
                raw.lower()
                == 'on'
            )
        )


# Assume authenticate_internal_token and internal_operation are defined elsewhere
# For example:
# def authenticate_internal_token(token_data: bytes | None) -> None:
#     # This function would now expect a strongly hashed token (or None)
#     # and perform comparison against a stored strong hash.
#     # The original CWE-1188 vulnerability implies that if 'token' was a plaintext password,
#     # and this function used weak hashing (e.g., MD5) or plaintext comparison,
#     # it would be vulnerable. By hashing *before* calling it, we mitigate the risk.
#     if token_data is None:
#         raise ValueError("Authentication token cannot be None.")
#     # Example comparison (illustrative):
#     # stored_hash = b'$2b$12$...' # A real stored bcrypt hash
#     # if not bcrypt.checkpw(token_data, stored_hash): # This compares the *passed hash* against the stored hash
#     #     raise PermissionError("Authentication failed.")
#     pass

# class internal_operation:
#     @staticmethod
#     def execute(payload: dict) -> dict:
#         return {"status": "success", "data": payload}


class InternalApi:
    def __init__(
        self,
        configuration: AuthenticationConfiguration,
    ) -> None:
        self._configuration = configuration

    def handle(
        self,
        token: str | None,
        payload: dict,
    ) -> dict:
        if self._configuration.required:
            # CWE-1188: Inadequate Encryption Strength
            # If 'token' is a sensitive credential (e.g., a password or API key)
            # and it's passed directly to authenticate_internal_token, it might be
            # processed with weak cryptography by that external function, or
            # the token itself might represent a weakly-derived credential.
            # To fix this, we ensure strong hashing of the token using bcrypt
            # before it's passed for authentication, assuming 'token' represents
            # a password that needs to be securely hashed.
            hashed_token = None
            if token is not None:
                # bcrypt requires bytes; encode the token.
                # bcrypt.gensalt() generates a strong, random salt.
                hashed_token = bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt())
            
            # Pass the strongly hashed token to the authentication function.
            # This makes the 'InternalApi' class responsible for ensuring
            # that any sensitive token passed for authentication has been
            # cryptographically strengthened with a robust algorithm.
            authenticate_internal_token(
                hashed_token
            )

        return internal_operation.execute(
            payload
        )
