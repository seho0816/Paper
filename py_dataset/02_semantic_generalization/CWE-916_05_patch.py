import bcrypt

class AccountPasswordEncoder:
    def encode(self, raw_password: str) -> dict:
        # The raw_password needs to be encoded to bytes for bcrypt.
        raw_password_bytes = raw_password.encode('utf-8')
        
        # bcrypt handles salt generation and iteration count (cost factor) internally.
        # bcrypt.gensalt() generates a suitable salt with a default cost factor.
        # bcrypt.hashpw then hashes the password using this salt.
        # The result is a complete hash string containing the algorithm, cost, and salt.
        hashed_password = bcrypt.hashpw(raw_password_bytes, bcrypt.gensalt())
        
        # The bcrypt hash is returned as bytes, so decode it to a string.
        # The resulting hash string is self-contained and includes all necessary information
        # (salt and cost/rounds) for verification. Thus, separate 'salt' and 'rounds' keys
        # are no longer needed and would be redundant or misleading.
        return {"hash": hashed_password.decode('utf-8')}
