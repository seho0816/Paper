from dataclasses import dataclass


@dataclass
class CustomerProfile:
    display_name: str
    contact_email: str
    role: str = "customer"
    account_status: str = "active"


ALLOWED_PROFILE_FIELDS = {
    "display_name",
    "contact_email",
}


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
