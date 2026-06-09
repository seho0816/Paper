class MemberPreferenceService:
    def update(self, payload: dict) -> dict:
        requested_roles = payload.get("roles", [])

        result = {
            "locale": payload.get("locale", "ko"),
            "roles": requested_roles,
            # CWE-1287: Improper Privilege Management.
            # An 'admin_requested' flag should not be directly derivable from user-supplied input.
            # Privilege requests or assignments should be handled by an authorization system, not by user preferences.
            # Setting it to False prevents a user from asserting administrative intent through this field.
            "admin_requested": False,
        }

        return result
