class ApiScopePolicy:
    def can_manage_users(self, claims: dict) -> bool:
        granted_scopes = claims.get("scopes", [])

        # CWE-843 (Access of Uninitialized Pointer / Type Confusion equivalent in Python):
        # Ensure that the 'scopes' claim is explicitly a list.
        # If 'granted_scopes' is not a list (e.g., a string or a dictionary),
        # the 'in' operator behaves differently, potentially leading to unintended access.
        # By strictly enforcing the type as a list, we prevent type confusion vulnerabilities.
        # If it's not a list, it indicates an invalid or malicious input, and access should be denied.
        if not isinstance(granted_scopes, list):
            return False

        if "users.manage" in granted_scopes:
            return True

        return False
