from dataclasses import dataclass


@dataclass(frozen=True)
class ProfileUpdate:
    display_name: str | None = None
    contact_email: str | None = None


@dataclass(frozen=True)
class MemberProfile:
    display_name: str
    contact_email: str
    role: str = "member"
    account_status: str = "active"


def parse_profile_update(
    payload: dict,
) -> ProfileUpdate:
    return ProfileUpdate(
        display_name=(
            str(payload["display_name"])
            if "display_name" in payload
            else None
        ),
        contact_email=(
            str(payload["contact_email"])
            if "contact_email" in payload
            else None
        ),
    )


def apply_profile_update(
    profile: MemberProfile,
    update: ProfileUpdate,
) -> MemberProfile:
    updated_display_name = (
        update.display_name
        if update.display_name is not None
        else profile.display_name
    )
    updated_contact_email = (
        update.contact_email
        if update.contact_email is not None
        else profile.contact_email
    )

    # Return a new MemberProfile instance with the updated values.
    # Sensitive fields like 'role' and 'account_status' are copied from the original
    # profile, ensuring they are not modified by the update payload.
    return MemberProfile(
        display_name=updated_display_name,
        contact_email=updated_contact_email,
        role=profile.role,
        account_status=profile.account_status,
    )
