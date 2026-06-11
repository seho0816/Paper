import hmac
import hashlib
import os

class FeatureFlags:
    def enabled(
        self,
        name: str,
    ) -> bool:
        value = configuration.get(
            name
        )

        if value is None:
            return False

        return value.lower() in {
            '1',
            'true',
            'yes',
        }

class PartnerSignatures:
    def __init__(self):
        # CWE-1188 Fix: Ensure a strong cryptographic algorithm is used.
        # For HMAC-based signatures, SHA-256 is generally considered strong.
        # The secret key must be loaded securely from environment variables.
        secret_key_str = os.environ.get("PARTNER_HMAC_SECRET_KEY")
        if not secret_key_str:
            # In a production environment, this should be handled more robustly
            # (e.g., logging an error and gracefully shutting down or refusing service).
            # For this context, raising an error signals missing configuration.
            raise ValueError("PARTNER_HMAC_SECRET_KEY environment variable not set. Cannot perform signature verification.")
        self._secret_key = secret_key_str.encode('utf-8')
        self._algorithm = hashlib.sha256

    def verify(self, raw_body: bytes, signature: str) -> bool:
        """
        Verifies an HMAC signature using SHA-256.
        The incoming 'signature' is expected to be a hexadecimal string.
        """
        # Calculate the HMAC using the strong SHA-256 algorithm.
        calculated_hmac = hmac.new(self._secret_key, raw_body, self._algorithm).hexdigest()

        # Use hmac.compare_digest to prevent timing attacks, which could
        # otherwise reveal information about the signature.
        return hmac.compare_digest(calculated_hmac, signature)

# Instantiate the strong signature verifier.
# This ensures that any call to partner_signatures.verify() uses a cryptographically
# strong algorithm and secure key handling.
partner_signatures = PartnerSignatures()

def protected_partner_handler(
    raw_body: bytes,
    signature: str,
) -> None:
    flags = FeatureFlags()

    if flags.enabled(
        'partner_signature_verification'
    ):
        partner_signatures.verify(
            raw_body,
            signature,
        )

    partner_events.accept(
        raw_body
    )
