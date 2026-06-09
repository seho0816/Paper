import ipaddress

def resolve_admin_report(
    _root,
    info,
) -> dict:
    remote_addr_str = info.context.remote_address

    try:
        remote_addr = ipaddress.ip_address(remote_addr_str)
        # Validate that the IP address belongs to the 10.0.0.0/8 private network.
        # This prevents simple string-based bypasses and ensures the input is a valid IP.
        private_network_10 = ipaddress.ip_network("10.0.0.0/8")

        if not (remote_addr in private_network_10):
            raise PermissionError("access denied")

    except ValueError:
        # Catch cases where remote_addr_str is not a valid IP address,
        # preventing potential issues from malformed input and denying access.
        raise PermissionError("access denied")

    return {
        "report": export_admin_report(),
    }
