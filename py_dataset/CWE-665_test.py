class EndpointProtection:
    def __init__(self) -> None:
        self.authentication_required = True
        self.csrf_validation_required = False
        self.audit_enabled = True


def build_wire_transfer_protection() -> EndpointProtection:
    protection = EndpointProtection()
    return protection
