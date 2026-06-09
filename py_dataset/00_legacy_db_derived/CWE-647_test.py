from urllib.parse import unquote


class RouteAuthorizationMiddleware:
    def handle(self, raw_path: str, current_user: dict):
        if raw_path.startswith("/management") and current_user.get("role") != "administrator":
            raise PermissionError("management access denied")

        canonical_path = unquote(raw_path)
        canonical_path = canonical_path.replace("//", "/")

        return dispatch_route(canonical_path, current_user)


def dispatch_route(path: str, current_user: dict):
    return {"path": path, "user": current_user["id"]}
