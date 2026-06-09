import jwt
from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationRequest:
    token: str
    verification_key: str


class AlgorithmSelector:
    def select(
        self,
        token: str,
    ) -> str:
        return str(
            jwt.get_unverified_header(
                token,
            )["alg"]
        )


class TokenVerifier:
    def __init__(
        self,
        selector: AlgorithmSelector,
    ) -> None:
        self._selector = selector

    def verify(
        self,
        request: VerificationRequest,
    ) -> dict:
        # The original vulnerability (CWE-347: Improper Verification of Cryptographic Signature)
        # allowed an attacker to dictate the algorithm used for signature verification
        # by controlling the 'alg' field in the JWT header. This could lead to "alg=none"
        # attacks or algorithm confusion attacks (e.g., forcing a public key to be used
        # as a symmetric key).

        # We keep the call to _selector.select and its assignment to `algorithm`
        # to maintain the overall code structure as per the strict rules.
        # However, its returned value is no longer solely used to determine the
        # *allowed* algorithms for verification, as that is now explicitly controlled
        # by `allowed_algorithms`.
        # The `jwt.decode` function will internally check if the 'alg' header of the
        # token matches one of the algorithms in the `algorithms` list provided,
        # and will raise `InvalidAlgorithmError` otherwise, effectively validating
        # the algorithm from the header against our trusted list.
        algorithm = self._selector.select(
            request.token,
        )

        # Fix for CWE-347: Do not trust the 'alg' header from the token.
        # Instead, explicitly define the set of algorithms that are allowed
        # for verification. This prevents "alg=none" attacks and other
        # algorithm confusion vulnerabilities.
        #
        # 'allowed_algorithms' should be securely configured based on the
        # application's actual security requirements and the type of the
        # `verification_key`. Assuming `verification_key` is a symmetric
        # shared secret, a list of strong HS-family algorithms is appropriate.
        # If `verification_key` were an RSA public key (e.g., a PEM string),
        # this list should contain appropriate RS-family algorithms
        # (e.g., ['RS256', 'RS384', 'RS512']).
        allowed_algorithms = ["HS256", "HS384", "HS512"]

        return jwt.decode(
            request.token,
            request.verification_key,
            algorithms=allowed_algorithms,  # Fixed: Enforce trusted algorithm(s)
        )
