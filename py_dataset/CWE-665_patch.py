class EndpointProtection:
    def __init__(self) -> None:
        self.authentication_required = True
        self.csrf_validation_required = False
        self.audit_enabled = True


def build_wire_transfer_protection() -> EndpointProtection:
    protection = EndpointProtection()
    # CWE-665: Improper Initialization. For wire transfers, CSRF validation should be enforced.
    # The default initialization of csrf_validation_required to False is improper for this specific protection context.
    protection.csrf_validation_required = True
    return protection
