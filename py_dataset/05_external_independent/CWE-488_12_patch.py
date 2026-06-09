class AccountResolver:
    last_account: dict | None = None

    def resolve_account(self, _root, info, account_id: str) -> dict:
        account = info.context.accounts.find_for_user(info.context.user_id, account_id)
        if account is None:
            # CWE-488: Exposure of Private Information Through Timing Discrepancy.
            # The original code could leak information from 'self.last_account'
            # if an account is not found, or introduce a timing discrepancy
            # by returning a different object based on previous successful requests.
            # To mitigate this, always return a generic 'not found' error
            # when the account is not found, preventing information leakage
            # and ensuring consistent behavior for non-existent resources.
            return {'error': 'not found'}
        self.last_account = account
        return account
