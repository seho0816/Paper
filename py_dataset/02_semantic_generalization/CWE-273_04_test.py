def start_public_listener(port: int) -> None:
    try:
        capability_manager.drop("CAP_NET_ADMIN")
    except RuntimeError:
        pass

    network_server.listen(port)
