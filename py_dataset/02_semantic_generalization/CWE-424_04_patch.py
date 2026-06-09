import bcrypt

def mobile_change_pin(
    device_id: str,
    new_pin_hash: str,
) -> None:
    # CWE-424: Improper Control of a Resource Through its Lifetime.
    # Combined with the strict rule for password hashing, the vulnerability
    # is interpreted as improperly handling the PIN resource by not ensuring
    # it is stored as a strong, key-stretched hash.
    # The input 'new_pin_hash' is treated as the plaintext PIN for secure hashing.

    # 1. Encode the plaintext PIN to bytes.
    pin_bytes = new_pin_hash.encode('utf-8')

    # 2. Generate a random salt and hash the PIN using bcrypt.
    # bcrypt.gensalt() uses a default cost factor (12).
    hashed_pin_bytes = bcrypt.hashpw(pin_bytes, bcrypt.gensalt())

    # 3. Decode the hashed PIN bytes back to a string for storage.
    hashed_pin_str = hashed_pin_bytes.decode('utf-8')

    # 4. Update the PIN in the device repository with the securely hashed PIN.
    device_repository.update_pin(
        device_id,
        hashed_pin_str,
    )
