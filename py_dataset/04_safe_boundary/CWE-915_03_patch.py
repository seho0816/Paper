from dataclasses import dataclass


@dataclass
class CustomerProfile:
    display_name: str
    contact_email: str
    role: str = "customer"
    account_status: str = "active"


# CWE-915 Fix: Convert ALLOWED_PROFILE_FIELDS to a frozenset.
# This makes the whitelist immutable, preventing runtime modification that could
# lead to unauthorized updates of attributes (e.g., if 'role' or 'account_status'
# was maliciously added to the set during execution). The original code used a mutable set,
# which could be altered by other parts of the application or by an attacker if
# they gain control over the application's global state.
ALLOWED_PROFILE_FIELDS = frozenset({
    "display_name",
    "contact_email",
})


def update_profile(
    profile: CustomerProfile,
    payload: dict,
) -> CustomerProfile:
    for field_name in ALLOWED_PROFILE_FIELDS:
        if field_name in payload:
            setattr(
                profile,
                field_name,
                str(payload[field_name]),
            )

    return profile
