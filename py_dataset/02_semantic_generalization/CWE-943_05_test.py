def read_json_value(
    redis_client,
    document_key: str,
    submitted_path: str,
):
    return redis_client.json().get(
        document_key,
        submitted_path,
    )
