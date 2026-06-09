import hashlib
import bcrypt

def set_account_pin(account_id: str, pin: str) -> None:
    # CWE-759: Use of a One-Way Hash without a Salt
    # Patched to use bcrypt, a strong key-stretching algorithm that automatically handles salting.
    # SHA-256 is not suitable for password/PIN storage without proper key-stretching and salting.
    pin_hash = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    pin_repository.save(account_id, pin_hash)
