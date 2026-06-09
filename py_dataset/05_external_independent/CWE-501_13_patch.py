def load_batch_actor(csv_header: dict[str, str]) -> dict:
    principal = {
        "staff_id": csv_header["submitted_by"],
        "department": csv_header["department"],
        "is_supervisor": False,  # CWE-501: Trust boundary violation fixed. 'is_supervisor' should not be controlled by untrusted input (csv_header).
    }
    batch_security.set_current(principal)
    return principal
