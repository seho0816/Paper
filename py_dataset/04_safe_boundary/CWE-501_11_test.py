class PrincipalResolver:
    def resolve(self, bearer_token: str) -> dict:
        claims = token_verifier.verify(bearer_token)
        account = account_repository.get_active(claims["sub"])
        if account is None or account.tenant_id != claims["tenant_id"]:
            raise PermissionError("invalid principal")
        return {
            "user_id": account.id,
            "tenant_id": account.tenant_id,
            "role": account.role,
        }
