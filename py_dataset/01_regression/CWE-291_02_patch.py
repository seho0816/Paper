import ipaddress

ALLOWED_BACKUP_IPS = {
    "192.168.1.20",
    "192.168.1.21",
}


def download_backup(
    remote_addr: str,
    backup_id: str,
) -> bytes:
    try:
        # Validate that remote_addr is a syntactically correct IP address.
        # This prevents a trust boundary violation where an attacker might
        # provide a malformed string that is not a proper IP address,
        # potentially bypassing or misinterpreting security checks.
        ip_obj = ipaddress.ip_address(remote_addr)
        # Convert it back to a standard string representation to ensure consistent comparison
        # with ALLOWED_BACKUP_IPS, which contains standard string representations.
        validated_remote_addr = str(ip_obj)
    except ValueError:
        # If remote_addr is not a valid IP address format, raise an error.
        raise PermissionError("invalid network address format")

    if validated_remote_addr not in ALLOWED_BACKUP_IPS:
        raise PermissionError(
            "network location denied"
        )

    return backup_repository.read(
        backup_id
    )
