import bcrypt # bcrypt for secure password hashing
import hashlib # Keep if there are other usages not touched by this patch, though not strictly needed here after the change.

def resolve_signup(_root, info, email: str, password: str) -> dict:
    account_id = info.context.accounts.next_identifier()
    
    # CWE-760: Replaced hashlib.pbkdf2_hmac with bcrypt.hashpw
    # bcrypt automatically generates a strong, random salt (preventing poor salt issues)
    # and handles key stretching with a configurable cost factor (rounds).
    # The prompt explicitly requires using bcrypt, argon2, or scrypt for password hashing.
    # A default rounds value of 12 is generally considered secure for bcrypt.
    digest = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    
    account = info.context.accounts.insert(account_id, email, digest)
    return {'account_id': account['id']}
