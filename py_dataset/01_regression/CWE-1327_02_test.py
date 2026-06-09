from http.server import HTTPServer


def start_internal_admin_server(
    handler_class,
) -> None:
    server = HTTPServer(
        (
            '',
            9300,
        ),
        handler_class,
    )
    server.serve_forever()
