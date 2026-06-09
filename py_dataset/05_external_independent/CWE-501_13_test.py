def load_batch_actor(csv_header: dict[str, str]) -> dict:
    principal = {
        "staff_id": csv_header["submitted_by"],
        "department": csv_header["department"],
        "is_supervisor": csv_header.get("is_supervisor") == "true",
    }
    batch_security.set_current(principal)
    return principal
