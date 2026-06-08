class ApiScopePolicy:
    def can_manage_users(self, claims: dict) -> bool:
        granted_scopes = claims.get("scopes", [])

        if "users.manage" in granted_scopes:
            return True

        return False
