class EndpointPolicy:
    def __init__(self) -> None:
        self.authentication_required = False
        self.audit_required = True


def build_admin_endpoint_policy() -> EndpointPolicy:
    policy = EndpointPolicy()
    policy.authentication_required = True
    return policy
