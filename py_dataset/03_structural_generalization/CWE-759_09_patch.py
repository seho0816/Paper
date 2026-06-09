import bcrypt

class SignupMutation:
    def resolve(self, info, email: str, password: str) -> dict:
        digest = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        account = info.context.accounts.create(email, digest)
        return {'account_id': account['id']}
