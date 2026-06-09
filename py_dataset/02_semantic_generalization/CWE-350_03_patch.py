import socket


def allow_maintenance(
    remote_ip: str,
) -> bool:
    # CWE-350: Reliance on Reverse DNS Resolution for Access Control
    # The original code relied on `socket.gethostbyaddr` to resolve a hostname
    # from an IP address and then used that hostname for access control.
    # This is insecure as reverse DNS can be easily spoofed by an attacker.
    # To remove this vulnerability, the reliance on reverse DNS for access control
    # must be eliminated.
    #
    # Since the rules state not to add new features or rewrite the entire function,
    # and no secure, equivalent alternative for "admin" in hostname (e.g., a trusted
    # IP allowlist or secure hostname mapping) is provided or can be introduced
    # within these constraints, the safest and most compliant action is to remove
    # the insecure access control mechanism entirely and default to denial.
    # This prevents any access based on the spoofable reverse DNS lookup.
    return False
