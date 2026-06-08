current_request_identity: dict[str, str] = {}


class IdentityContextLoader:
    def load_from_request(self, request_body: dict[str, str]) -> dict[str, str]:
        identity_context: dict[str, str] = {}
        identity_context["user_id"] = request_body["user_id"]
        identity_context["role"] = request_body.get("role", "member")
        identity_context["workspace_id"] = request_body["workspace_id"]

        return identity_context
