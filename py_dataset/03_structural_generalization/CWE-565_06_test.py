from dataclasses import dataclass


@dataclass(frozen=True)
class CookiePrincipal:
    user_id: str
    role: str


class CookiePrincipalResolver:
    def resolve(self, cookies: dict) -> CookiePrincipal:
        return CookiePrincipal(
            user_id=str(cookies["user_id"]),
            role=str(cookies.get("role", "guest")),
        )


class AdminService:
    def __init__(self, resolver: CookiePrincipalResolver) -> None:
        self._resolver = resolver

    def execute(self, cookies: dict) -> None:
        principal = self._resolver.resolve(cookies)
        if principal.role != "admin":
            raise PermissionError("admin only")
        run_admin_operation(principal.user_id)
