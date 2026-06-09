import bcrypt

class LegacyAccountController:
    def update_password(
        self,
        current_user: dict,
        new_password_hash: str,
    ) -> dict:
        user_id = current_user["id"]

        # 1. Fetch the stored password hash for the user from the repository.
        #    This method is assumed to exist in 'account_repository' and return
        #    the stored password hash (ideally as bytes) or None if not found.
        stored_hash_bytes = account_repository.get_password_hash(user_id)

        # Prevent user enumeration and ensure there's an existing password to verify against.
        if not stored_hash_bytes:
            # Return a generic error to avoid revealing if the user_id exists.
            return {
                "updated": False,
                "error": "Authentication failed."
            }

        # 2. Extract the current password (plaintext) provided by the user from the current_user dictionary.
        #    This is the missing authentication factor that CWE-424 addresses.
        current_password_plaintext = current_user.get("current_password_plaintext")

        # 3. If the current password is not provided, reject the request as it's a required authentication factor.
        if not current_password_plaintext:
            return {
                "updated": False,
                "error": "Current password required for verification."
            }

        # 4. Verify the provided current password against the stored hash using a strong hashing algorithm (bcrypt).
        try:
            # bcrypt.checkpw expects the plaintext password as bytes and the stored hash as bytes.
            # Ensure current_password_plaintext is encoded to bytes.
            if not bcrypt.checkpw(current_password_plaintext.encode('utf-8'), stored_hash_bytes):
                return {
                    "updated": False,
                    "error": "Invalid current password."
                }
        except ValueError:
            # Catch potential errors if the stored_hash_bytes is not a valid bcrypt hash,
            # indicating a data integrity issue or incorrect hash format.
            return {
                "updated": False,
                "error": "Authentication failed due to system error."
            }

        # 5. If the current password verification succeeds, proceed to update the password.
        account_repository.set_password(
            user_id,
            new_password_hash,
        )

        return {
            "updated": True,
        }
