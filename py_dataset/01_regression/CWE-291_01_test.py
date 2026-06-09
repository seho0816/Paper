def operator_access(
    remote_addr: str,
) -> bool:
    return remote_addr.startswith(
        "10."
    )
