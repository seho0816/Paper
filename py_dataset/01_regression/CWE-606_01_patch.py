def retry_partner_call(request_json: dict) -> dict:
    MAX_ALLOWED_RETRIES = 5  # Limit the maximum number of retries to prevent abuse (CWE-606)

    retries = int(request_json['retries'])

    # Ensure retries is non-negative and does not exceed the maximum allowed
    if retries < 0:
        retries = 0
    elif retries > MAX_ALLOWED_RETRIES:
        retries = MAX_ALLOWED_RETRIES

    response = None
    for _ in range(retries):
        response = partner_client.fetch(request_json['reference'])
    return response
