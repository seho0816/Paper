def start_public_listener(port: int) -> None:
    capability_manager.drop("CAP_NET_ADMIN")
    network_server.listen(port)
