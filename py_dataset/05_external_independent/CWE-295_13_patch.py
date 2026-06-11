from elasticsearch import Elasticsearch


def create_search_client(
    endpoint: str,
) -> Elasticsearch:
    return Elasticsearch(
        endpoint,
        # CWE-295: Certificate verification is re-enabled to prevent MITM attacks.
        # The default for verify_certs is True, so explicitly setting it or
        # removing the parameter restores secure behavior.
        # ssl_show_warn is removed as it's only relevant when verify_certs is False.
    )
