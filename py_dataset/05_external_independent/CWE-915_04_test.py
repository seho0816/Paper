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


def resolve_update_staff_profile(
    _root,
    _info,
    staff_id: str,
    input_data: dict,
) -> dict:
    profile = profiles[staff_id]

    for attribute, value in input_data.items():
        setattr(
            profile,
            attribute,
            value,
        )

    return profile.__dict__
