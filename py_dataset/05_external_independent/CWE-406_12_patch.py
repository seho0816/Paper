import os

# Assume AUTHORIZED_TENANT_QUERY_IPS is a comma-separated string of allowed client IP addresses
# e.g., "192.168.1.10,10.0.0.5"
AUTHORIZED_CLIENTS_STR = os.environ.get("AUTHORIZED_TENANT_QUERY_IPS", "")
AUTHORIZED_CLIENTS = set(ip.strip() for ip in AUTHORIZED_CLIENTS_STR.split(',') if ip.strip())

def handle_tenant_query(
    udp_socket,
    request: bytes,
    client_address,
) -> None:
    # CWE-406 Fix: Implement control over who can query for tenants.
    # This prevents unauthorized access and potential resource exhaustion (Denial of Service)
    # by limiting the operation to a set of pre-approved client IP addresses.
    if client_address[0] not in AUTHORIZED_CLIENTS:
        return

    if request != b"TENANTS":
        return

    payload = serialize_tenants(
        tenant_repository.find_all()
    )
    udp_socket.sendto(
        payload,
        client_address,
    )
