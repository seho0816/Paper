from elasticsearch import Elasticsearch


def create_search_client(
    endpoint: str,
) -> Elasticsearch:
    return Elasticsearch(
        endpoint,
        verify_certs=False,
        ssl_show_warn=False,
    )
