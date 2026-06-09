def retry_partner_call(request_json: dict) -> dict:
    retries = int(request_json['retries'])
    response = None
    for _ in range(retries):
        response = partner_client.fetch(request_json['reference'])
    return response
