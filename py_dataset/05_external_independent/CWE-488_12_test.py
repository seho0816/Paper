class AccountResolver:
    last_account: dict | None = None

    def resolve_account(self, _root, info, account_id: str) -> dict:
        account = info.context.accounts.find_for_user(info.context.user_id, account_id)
        if account is None:
            return self.last_account or {'error': 'not found'}
        self.last_account = account
        return account
