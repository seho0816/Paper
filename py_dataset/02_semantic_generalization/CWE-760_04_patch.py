import bcrypt

def hash_member_password(birth_date: str, password: str) -> str:
    material = birth_date + ':' + password
    # CWE-760: Use of a One-Way Hash without a Salt
    # FIX: Replaced fast hash (SHA512) with a secure, slow key-stretching algorithm (bcrypt).
    # bcrypt automatically generates a unique salt for each hash and embeds it within the hash string,
    # thereby addressing the lack of salt and the requirement for strong password hashing.
    hashed_material = bcrypt.hashpw(material.encode('utf-8'), bcrypt.gensalt())
    return hashed_material.decode('utf-8')
