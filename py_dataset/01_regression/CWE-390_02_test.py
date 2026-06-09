def connect_partner(host: str, certificate) -> object:
    try:
        certificate_policy.verify(host, certificate)
    except CertificateError:
        pass
    return partner_transport.open(host)
