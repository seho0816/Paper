from fastapi import Request
from urllib.parse import urlencode


def payment_return_url(
    request: Request,
    order_id: str,
) -> str:
    # CWE-348 fix: The original code hardcoded the query parameter structure
    # and directly concatenated `order_id` without URL encoding.
    # This represents a hardcoded insecure pattern for handling a security-relevant
    # parameter (order_id in a payment context).
    #
    # To mitigate this, `order_id` must be properly URL-encoded to prevent
    # URL parameter tampering or injection if `order_id` contains special characters
    # like '&', '=', or spaces.
    # `urlencode` is used to safely encode the `order_id` parameter.
    
    encoded_params = urlencode({"order_id": order_id})
    
    return (
        str(
            request.base_url
        )
        + "payments/complete?"
        + encoded_params
    )
