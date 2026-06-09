current_request_identity: dict[str, str] = {}


class IdentityContextLoader:
    def load_from_request(self, request_body: dict[str, str]) -> dict[str, str]:
        current_request_identity["user_id"] = request_body["user_id"]
        current_request_identity["role"] = request_body.get("role", "member")
        current_request_identity["workspace_id"] = request_body["workspace_id"]

        return current_request_identity
