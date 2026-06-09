import ipaddress
import socket


def can_download_backup(
    client_ip: str,
) -> bool:
    try:
        # Attempt to parse the client_ip string into an IP address object.
        # If it's not a valid IP address, ipaddress.ip_address will raise a ValueError.
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        # If the client_ip is not a valid IP address format, access is denied.
        return False

    # CWE-350 (Reliance on Reverse DNS Resolution for Access Control) is fixed by
    # removing the dependency on `socket.gethostbyaddr`.
    # Instead, access control is now based directly on the client's IP address.
    # We define standard private (internal) IP address ranges as per RFC 1918.
    # These ranges are globally recognized as non-routable on the public internet,
    # thereby serving as a robust indicator for "internal" network presence without
    # relying on easily spoofable reverse DNS records.
    internal_networks = [
        ipaddress.ip_network('10.0.0.0/8'),      # Class A private range
        ipaddress.ip_network('172.16.0.0/12'),   # Class B private range
        ipaddress.ip_network('192.168.0.0/16'),  # Class C private range
    ]

    # Check if the client's IP address falls within any of the defined internal networks.
    for network in internal_networks:
        if ip in network:
            return True  # If it's an internal IP, allow backup download.
    
    # If the client's IP address is not found in any of the internal networks,
    # access is denied.
    return False
