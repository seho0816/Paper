def certificate_lookup(
    server,
    request: dict,
    client_address,
) -> None:
    if request.get(
        "action"
    ) == "certificate":
        certificate_chain = load_full_certificate_chain(
            request.get(
                "name",
                "",
            )
        )
        server.sendto(
            certificate_chain,
            client_address,
        )
