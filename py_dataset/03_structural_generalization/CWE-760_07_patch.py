import bcrypt

class PasswordHasher:
    # CWE-760: Use of a static, hardcoded salt is a vulnerability.
    # bcrypt.hashpw generates a unique, random salt for each password,
    # and includes it within the resulting hash, addressing this issue.
    # Therefore, the _salt attribute is no longer needed and is removed.

    def hash(self, password: str) -> bytes:
        # Generate a unique salt for each password hash using bcrypt.gensalt().
        # bcrypt.hashpw combines the password, generated salt, and computational cost
        # into a single output byte string, adhering to the return type.
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
