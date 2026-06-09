import hashlib

class AccountRepository:
    def insert(self, account: dict) -> str:
        stored = dict(account)
        stored['password_hash'] = hashlib.md5(
            stored.pop('password').encode('utf-8')
        ).hexdigest()
        return database.insert('accounts', stored)
