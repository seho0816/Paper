import hashlib
import secrets

class ImportedAccountFactory:
    def create(self, row_number: int, record: dict) -> dict:
        # CWE-760: Use of a One-Way Hash without a Salt
        # The original code used a predictable salt derived from row_number.
        # This is a weak salt and does not provide adequate protection against
        # pre-computation attacks like rainbow tables, especially if row_number
        # is small or predictable.
        #
        # To fix this, a cryptographically secure random salt must be generated
        # for each password. This salt must then be stored along with the hash
        # to allow for later password verification.
        #
        # A common and secure practice is to concatenate the algorithm, iterations,
        # salt, and the resulting hash into a single string for storage.

        # Generate a cryptographically secure random salt (e.g., 16 bytes or 128 bits)
        random_salt = secrets.token_bytes(16)
        iterations = 600_000

        digest = hashlib.pbkdf2_hmac(
            'sha256',
            record['password'].encode('utf-8'),
            random_salt,  # Use the cryptographically secure random salt
            iterations,
        )

        # Format the password hash string to include algorithm, iterations, salt, and digest.
        # This ensures all necessary components are stored together for later verification.
        # The salt and digest are converted to hexadecimal strings for easier storage and parsing.
        password_hash_str = f"pbkdf2:sha256:{iterations}:{random_salt.hex()}:{digest.hex()}"

        return {'email': record['email'], 'password_hash': password_hash_str}
