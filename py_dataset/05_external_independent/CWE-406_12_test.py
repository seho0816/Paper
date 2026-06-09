def handle_tenant_query(
    udp_socket,
    request: bytes,
    client_address,
) -> None:
    if request != b"TENANTS":
        return

    payload = serialize_tenants(
        tenant_repository.find_all()
    )
    udp_socket.sendto(
        payload,
        client_address,
    )
