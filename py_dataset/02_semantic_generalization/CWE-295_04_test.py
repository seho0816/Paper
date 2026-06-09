import urllib3


def create_http_client() -> urllib3.PoolManager:
    return urllib3.PoolManager(
        cert_reqs="CERT_NONE",
    )
