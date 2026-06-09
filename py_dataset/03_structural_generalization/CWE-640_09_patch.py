import os
import hmac
import hashlib
import base64
from dataclasses import dataclass


@dataclass
class RecoveryChallenge:
    token: str
    account_id: str
    expires_at: int
    consumed: bool = False


# Placeholder for external function to update password
# This function's implementation is outside the scope of this fix.
def update_password(account_id: str, new_password: str):
    pass


class RecoveryService:
    # CWE-640 Fix: Load a secret key from an environment variable for HMAC validation.
    # This key is essential for generating and verifying secure tokens.
    # Rule 7: The environment variable "RECOVERY_TOKEN_SECRET" must be set in the environment.
    _SECRET_KEY = os.environ["RECOVERY_TOKEN_SECRET"].encode('utf-8')

    def reset(
        self,
        challenge: RecoveryChallenge,
        new_password: str,
        now: int,
    ) -> bool:
        # CWE-640 Fix: Add token validation as the first step.
        # This ensures that the provided RecoveryChallenge object's token is legitimate
        # and has not been tampered with or fabricated by an attacker.
        if not self._validate_challenge_token(challenge):
            return False

        if challenge.consumed:
            return False

        if challenge.expires_at < now:
            return False

        update_password(
            challenge.account_id,
            new_password,
        )

        return True

    def _validate_challenge_token(self, challenge: RecoveryChallenge) -> bool:
        """
        Validates the recovery challenge token using HMAC.
        The token is expected to be a base64-encoded string structured as:
        "{account_id}.{expires_at}.{hmac_digest}"
        This method verifies the HMAC and ensures the data embedded in the token
        matches the data in the provided RecoveryChallenge object.
        """
        token = challenge.token
        expected_account_id = challenge.account_id
        expected_expires_at = challenge.expires_at

        try:
            # Decode the full base64-encoded token string
            decoded_full_token = base64.urlsafe_b64decode(token).decode('utf-8')
            parts = decoded_full_token.split('.')

            # Ensure the token has the expected three parts: account_id, expires_at, and digest
            if len(parts) != 3:
                return False

            token_account_id_str, token_expires_at_str, received_digest_b64 = parts

            # Reconstruct the data that was originally signed to calculate the expected HMAC
            data_to_sign = f"{token_account_id_str}.{token_expires_at_str}".encode('utf-8')

            # Calculate the expected HMAC digest using the shared secret key
            h = hmac.new(self._SECRET_KEY, data_to_sign, hashlib.sha256)
            expected_digest_b64 = base64.urlsafe_b64encode(h.digest()).decode('utf-8')

            # Compare the received digest with the expected digest in a constant-time manner.
            # This is crucial to prevent timing attacks that could reveal information about the digest.
            if not hmac.compare_digest(received_digest_b64.encode('utf-8'), expected_digest_b64.encode('utf-8')):
                return False

            # After verifying the HMAC, ensure that the data extracted from the token
            # matches the corresponding fields in the `RecoveryChallenge` object.
            # This prevents an attacker from using a valid token for account_A to reset account_B's password.
            if not (token_account_id_str == expected_account_id and int(token_expires_at_str) == expected_expires_at):
                return False

            return True

        except (ValueError, TypeError, AttributeError):
            # Catch errors that might occur during decoding, splitting, integer conversion,
            # or accessing attributes if the token format is unexpected or malformed.
            return False
        except Exception:
            # Catch any other unexpected exceptions during the validation process
            return False
