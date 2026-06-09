def connect_partner(host: str, certificate) -> object:
    try:
        certificate_policy.verify(host, certificate)
    except CertificateError:
        raise
    return partner_transport.open(host)
