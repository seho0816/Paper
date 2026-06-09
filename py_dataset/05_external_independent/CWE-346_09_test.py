def on_socket_connect(
    environ: dict,
) -> bool:
    origin = environ.get(
        "HTTP_ORIGIN"
    )
    register_connection(
        environ
    )

    return True
