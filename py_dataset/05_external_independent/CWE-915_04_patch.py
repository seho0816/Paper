from dataclasses import dataclass


@dataclass
class StaffProfile:
    display_name: str
    department: str
    is_supervisor: bool = False
    payroll_grade: int = 1


profiles = {
    "staff-90": StaffProfile(
        display_name="employee",
        department="sales",
    ),
}

# Define a whitelist of attributes that are allowed to be modified by the user.
# This prevents unauthorized modification of sensitive attributes like 'is_supervisor' or 'payroll_grade'.
ALLOWED_STAFF_PROFILE_UPDATE_ATTRIBUTES = {
    "display_name",
    "department",
}


def resolve_update_staff_profile(
    _root,
    _info,
    staff_id: str,
    input_data: dict,
) -> dict:
    profile = profiles[staff_id]

    for attribute, value in input_data.items():
        # Only set attributes that are explicitly whitelisted.
        if attribute in ALLOWED_STAFF_PROFILE_UPDATE_ATTRIBUTES:
            setattr(
                profile,
                attribute,
                value,
            )
        # Attributes not in the whitelist will be ignored, preventing CWE-915.

    return profile.__dict__
