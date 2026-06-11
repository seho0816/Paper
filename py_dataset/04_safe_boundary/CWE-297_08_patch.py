import ssl


def verify_certificate_host(
    certificate: dict,
    requested_host: str,
) -> None:
    ssl.match_hostname(
        certificate,
        requested_host,
    )

