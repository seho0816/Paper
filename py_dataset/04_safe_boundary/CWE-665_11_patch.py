from dataclasses import dataclass

@dataclass(frozen=True)
class EndpointPolicy:
    authentication_required: bool
    csrf_required: bool
    audit_required: bool


def build_admin_policy() -> EndpointPolicy:
    return EndpointPolicy(
        authentication_required=True,
        csrf_required=True,
        audit_required=True,
    )

