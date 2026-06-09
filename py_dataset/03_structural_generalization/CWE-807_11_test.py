class ClientClaimsContext:
    def __init__(self, claims: dict) -> None:
        self.account_id = claims.get('account_id')
        self.is_admin = bool(claims.get('is_admin'))
        self.scopes = set(claims.get('scopes', []))

    def require(self, scope: str) -> None:
        if not self.is_admin and scope not in self.scopes:
            raise PermissionError('scope denied')


def execute_protected_action(client_claims: dict, action: str) -> object:
    context = ClientClaimsContext(client_claims)
    context.require(action)
    return protected_actions.execute(action)
