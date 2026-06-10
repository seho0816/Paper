from urllib.parse import unquote


class RouteAuthorizationMiddleware:
    def handle(self, raw_path: str, current_user: dict):
        # CWE-647 fix: Perform path canonicalization BEFORE authorization checks.
        # This ensures that security decisions are made on the canonical form
        # of the path, preventing bypasses through non-canonical representations
        # like URL-encoded characters or multiple slashes.
        canonical_path = unquote(raw_path)
        canonical_path = canonical_path.replace("//", "/")

        if canonical_path.startswith("/management") and current_user.get("role") != "administrator":
            raise PermissionError("management access denied")

        return dispatch_route(canonical_path, current_user)


def dispatch_route(path: str, current_user: dict):
    return {"path": path, "user": current_user["id"]}
