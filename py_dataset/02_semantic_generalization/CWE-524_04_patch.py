import copy

def cache_partner_response(shared_cache, cache_key: str, headers: dict, body: dict) -> None:
    sanitized_request_headers = copy.deepcopy(headers)
    
    sensitive_header_keys = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
    }
    
    headers_to_remove = []
    for header_name in sanitized_request_headers:
        if header_name.lower() in sensitive_header_keys:
            headers_to_remove.append(header_name)
            
    for header_name in headers_to_remove:
        del sanitized_request_headers[header_name]

    shared_cache.set(
        cache_key,
        {
            "request_headers": sanitized_request_headers,
            "response_body": body,
        },
        ttl_seconds=300,
    )
