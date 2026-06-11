import bcrypt
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticationRequest:
    claimed_username: str
    credential: str


class IdentityDirectory:
    # This dictionary simulates a user credential store.
    # In a real application, this would be a database lookup
    # where passwords are securely hashed using a strong KDF like bcrypt.
    # We use a class-level variable as the original class does not have an __init__ method,
    # and we must maintain its structure strictly.
    _user_credentials = {
        # Store securely hashed passwords. Do not use 'placeholder' values.
        "user1": bcrypt.hashpw("secure_password_1".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        "admin": bcrypt.hashpw("super_secure_admin_pass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
    }

    def exists(
        self,
        username: str,
    ) -> bool:
        # This method's signature and body are maintained exactly as in the vulnerable code.
        # It implies an external 'directory' object with a 'user_exists' method.
        # For the purpose of fixing CWE-287, we introduce credential verification separately.
        return directory.user_exists(
            username,
        )

    # Added method to perform secure credential verification.
    def verify_credential(
        self,
        username: str,
        credential: str,
    ) -> bool:
        hashed_password = self._user_credentials.get(username)

        # If username is not found in our credential store, or no password set, return False.
        if hashed_password is None:
            return False

        try:
            # Securely compare the provided credential with the stored hashed password.
            # Using bcrypt.checkpw to prevent timing attacks.
            return bcrypt.checkpw(credential.encode('utf-8'), hashed_password.encode('utf-8'))
        except ValueError:
            # Handle cases where the stored hash might be malformed or not a bcrypt hash.
            # This could indicate data corruption or an invalid hash format.
            return False


class AuthenticationManager:
    def __init__(
        self,
        directory: IdentityDirectory,
    ) -> None:
        self._directory = directory

    def authenticate(
        self,
        request: AuthenticationRequest,
    ) -> dict | None:
        # First, check if the user exists in the directory.
        if not self._directory.exists(
            request.claimed_username,
        ):
            return None

        # CWE-287 fix: After confirming user existence,
        # securely verify the provided credential against the stored one.
        if not self._directory.verify_credential(
            request.claimed_username,
            request.credential,
        ):
            return None  # Credential does not match, authentication fails.

        # If both existence and credential verification pass, then authentication is successful.
        return {
            "principal": request.claimed_username,
            "authenticated": True,
        }
