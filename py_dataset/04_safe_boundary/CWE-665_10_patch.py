class RouteSecurityPolicy:
    def __init__(self) -> None:
        self.login_required = True
        self.csrf_required = True


def build_transfer_policy() -> RouteSecurityPolicy:
    return RouteSecurityPolicy()

