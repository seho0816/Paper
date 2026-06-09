class MemberPreferenceService:
    def update(self, payload: dict) -> dict:
        requested_roles = payload.get("roles", [])

        result = {
            "locale": payload.get("locale", "ko"),
            "roles": requested_roles,
            "admin_requested": "admin" in requested_roles,
        }

        return result
