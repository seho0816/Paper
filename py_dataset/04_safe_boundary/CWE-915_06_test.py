from dataclasses import dataclass


@dataclass(frozen=True)
class ProfileUpdate:
    display_name: str | None = None
    contact_email: str | None = None


@dataclass
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
    if update.display_name is not None:
        profile.display_name = update.display_name

    if update.contact_email is not None:
        profile.contact_email = update.contact_email

    return profile
