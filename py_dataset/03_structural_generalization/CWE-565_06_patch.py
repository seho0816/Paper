import os
import json
import hmac
import hashlib
import base64
from dataclasses import dataclass

# Assuming APP_SECRET_KEY is securely set in the environment.
# Direct access to os.environ ensures a KeyError if the variable is not set,
# enforcing a strong security posture by failing fast if configuration is incomplete.
_APP_SECRET_KEY = os.environ["APP_SECRET_KEY"].encode('utf-8')


@dataclass(frozen=True)
class CookiePrincipal:
    user_id: str
    role: str


class CookiePrincipalResolver:
    # CWE-565: Reliance on Cookies without Validation and Integrity Checking.
    # The original `resolve` method directly trusted `cookies["user_id"]` and `cookies.get("role")`.
    # To fix this, we introduce cryptographic signing to ensure the integrity of the principal data
    # stored in a cookie. The resolver will now expect a single, securely signed cookie
    # containing the principal's information.

    def _sign_data(self, data: bytes) -> bytes:
        """Signs the given byte data using HMAC-SHA256 and base64-encodes the result."""
        signature = hmac.new(_APP_SECRET_KEY, data, hashlib.sha256).digest()
        # Combine signature and data, then base64-encode for safe cookie storage
        return base64.urlsafe_b64encode(signature + data)

    def _unsign_data(self, signed_data: bytes) -> bytes | None:
        """Unsigns and verifies the given base64-encoded, signed byte data.
        Returns the original data if the signature is valid, otherwise None.
        """
        try:
            # Base64-decode the combined signature and data
            decoded = base64.urlsafe_b64decode(signed_data)
            
            # Extract the signature part
            signature_len = hashlib.sha256().digest_size
            signature = decoded[:signature_len]
            
            # Extract the original data part
            data = decoded[signature_len:]
            
            # Re-calculate the expected signature
            expected_signature = hmac.new(_APP_SECRET_KEY, data, hashlib.sha256).digest()

            # Compare signatures in a constant-time manner to prevent timing attacks
            if hmac.compare_digest(signature, expected_signature):
                return data
            else:
                return None  # Signature mismatch, data was tampered with
        except (TypeError, ValueError, IndexError):
            # Handle malformed base64 or corrupted data during decoding/slicing
            return None

    def resolve(self, cookies: dict) -> CookiePrincipal:
        # We now expect a single, signed cookie (e.g., '_principal_session')
        # instead of direct, untrusted 'user_id' and 'role' cookies.
        principal_cookie_value = cookies.get("_principal_session")

        if not principal_cookie_value:
            # If no secure principal cookie is found, return a default guest principal.
            return CookiePrincipal(user_id="anonymous", role="guest")

        try:
            # 1. Attempt to unsign the cookie value to verify its integrity.
            # Convert the cookie string to bytes for cryptographic operations.
            unsigned_bytes = self._unsign_data(principal_cookie_value.encode('utf-8'))
            if unsigned_bytes is None:
                # Signature verification failed, meaning the cookie was tampered with or malformed.
                return CookiePrincipal(user_id="anonymous", role="guest")

            # 2. Decode the unsigned bytes into a JSON string and parse it.
            principal_data_str = unsigned_bytes.decode('utf-8')
            principal_data = json.loads(principal_data_str)

            # 3. Extract and validate user_id and role from the deserialized data.
            user_id = principal_data.get("user_id")
            # Maintain the original behavior of defaulting 'role' to 'guest'.
            role = principal_data.get("role", "guest")

            # Basic type validation for extracted data.
            if not isinstance(user_id, str):
                # If user_id is not a string, the data is invalid.
                return CookiePrincipal(user_id="anonymous", role="guest")

            # Return the securely resolved principal.
            return CookiePrincipal(user_id=user_id, role=role)

        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, ValueError):
            # Catch any errors during JSON parsing, decoding, or data access,
            # indicating a corrupted or unexpected cookie format.
            return CookiePrincipal(user_id="anonymous", role="guest")


class AdminService:
    def __init__(self, resolver: CookiePrincipalResolver) -> None:
        self._resolver = resolver

    def execute(self, cookies: dict) -> None:
        principal = self._resolver.resolve(cookies)
        if principal.role != "admin":
            raise PermissionError("admin only")
        run_admin_operation(principal.user_id)


# Placeholder function to maintain the original code structure and ensure it's runnable.
def run_admin_operation(user_id: str) -> None:
    pass
