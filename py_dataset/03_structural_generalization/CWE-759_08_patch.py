import bcrypt

class AccountRepository:
    def insert(self, account: dict) -> str:
        stored = dict(account)
        password_plain = stored.pop('password').encode('utf-8')
        # CWE-759 fix: Replaced insecure MD5 without salt with bcrypt
        # bcrypt.gensalt() generates a random salt, addressing the "without a salt" part of CWE-759
        # bcrypt also provides key stretching, making it suitable for password hashing
        stored['password_hash'] = bcrypt.hashpw(password_plain, bcrypt.gensalt()).decode('utf-8')
        return database.insert('accounts', stored)
