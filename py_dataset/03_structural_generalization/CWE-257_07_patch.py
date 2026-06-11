import bcrypt

# The 'database' and 'password_cipher' objects are assumed to exist in the environment
# as external dependencies, consistent with the original vulnerable code.
# Their internal implementations are conceptually updated to handle password hashes.

class RecoverablePasswordStore:
    def load_plaintext(
        self,
        account_id: str,
    ) -> str:
        # CWE-257 fix: Passwords must not be stored in a recoverable (plaintext) format.
        # This method's name 'load_plaintext' is misleading after the fix but must be kept
        # as per the strict rules. It now returns a cryptographically secure password hash.
        # It is assumed that 'database.load_password_blob' now retrieves a bcrypt hash
        # (which is a string) instead of an encrypted plaintext password blob.
        # The 'password_cipher.decrypt' step is removed, as we are loading a hash directly.
        stored_hash = database.load_password_blob(
            account_id
        )
        
        # If no hash is found for the account, return an empty string.
        # This allows the caller to handle the absence of a stored password gracefully
        # without exposing account existence (user enumeration prevention via timing attacks).
        return stored_hash if stored_hash is not None else ""


class AuthenticationService:
    def __init__(
        self,
        store: RecoverablePasswordStore,
    ) -> None:
        self._store = store

    def authenticate(
        self,
        account_id: str,
        submitted_password: str,
    ) -> bool:
        # Retrieve the stored password hash using the (now renamed in function) load_plaintext method.
        stored_hash = self._store.load_plaintext(
            account_id
        )

        # If no hash is stored (e.g., account does not exist or password not set),
        # authentication fails. This also helps prevent user enumeration attacks.
        if not stored_hash:
            return False

        try:
            # CWE-257 fix: Use bcrypt.checkpw to securely compare the submitted password
            # with the stored hash. This prevents direct comparison of plaintext passwords
            # and leverages a strong, key-stretching hashing algorithm.
            # Both the submitted password and the stored hash must be encoded to bytes for bcrypt.
            return bcrypt.checkpw(
                submitted_password.encode("utf-8"),
                stored_hash.encode("utf-8")
            )
        except ValueError:
            # Catch ValueError if 'stored_hash' is not a valid bcrypt hash string (e.g., corrupted data).
            # In such cases, authentication should fail for security reasons.
            return False
