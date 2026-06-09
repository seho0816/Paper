def resolve_request_role(
    remote_addr: str,
) -> str:
    if remote_addr in {
        "10.10.0.8",
        "10.10.0.9",
    }:
        return "admin"

    return "user"
