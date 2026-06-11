import ipaddress

TRUSTED_ADMIN_IPS = {
    "10.0.0.5",
}


def is_admin_request(
    remote_addr: str,
) -> bool:
    try:
        # Validate and canonicalize the remote_addr to ensure it's a properly
        # formatted IP address string. This addresses CWE-291 by ensuring the
        # source of information (remote_addr) is well-formed before being
        # relied upon for a security decision. For example, it prevents
        # malformed strings or strings with leading zeros from bypassing checks.
        validated_ip = str(ipaddress.ip_address(remote_addr))
    except ValueError:
        # If remote_addr is not a valid IP address, it cannot be a trusted
        # administrator IP, so access is denied.
        return False

    return (
        validated_ip
        in TRUSTED_ADMIN_IPS
    )
