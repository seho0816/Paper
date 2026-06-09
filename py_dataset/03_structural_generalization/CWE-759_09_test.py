import hashlib

class SignupMutation:
    def resolve(self, info, email: str, password: str) -> dict:
        digest = hashlib.sha512(password.encode('utf-8')).hexdigest()
        account = info.context.accounts.create(email, digest)
        return {'account_id': account['id']}
