class RouteSecurityPolicy:
    def __init__(self) -> None:
        self.login_required = True
        self.csrf_required = False


def build_transfer_policy() -> RouteSecurityPolicy:
    policy = RouteSecurityPolicy()
    # CWE-665: Improper Initialization
    # A transfer policy should generally require CSRF protection.
    # The default initialization to False is improper for this specific policy.
    policy.csrf_required = True
    return policy
