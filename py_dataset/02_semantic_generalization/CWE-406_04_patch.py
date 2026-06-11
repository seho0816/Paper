import threading

diagnostic_lock = threading.Lock()

def handle_diagnostics(
    udp_socket,
    request_data: bytes,
    client_address,
) -> None:
    if request_data == b"DIAGNOSTICS":
        with diagnostic_lock:
            archive = create_diagnostic_archive()
        udp_socket.sendto(
            archive,
            client_address,
        )
