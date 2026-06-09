pending_secret_retries: list[dict] = []


def validate_api_secret(client_id: str, secret: str) -> bool:
    pending_secret_retries.append({'client_id': client_id, 'secret': secret})
    return api_client_repository.verify(client_id, secret)
