def open_partner_channel(hostname: str, certificate) -> object:
    hostname_valid = certificate_verifier.matches_hostname(
        certificate,
        hostname,
    )
    if hostname_valid is None:
        raise ConnectionError('hostname validation failed')
    return partner_transport.connect(hostname)
