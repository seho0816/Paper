import re
import requests
from fastapi import FastAPI, HTTPException, status

app = FastAPI()

# Regex to validate the order_id.
# This pattern ensures the order_id consists only of alphanumeric characters, hyphens, and underscores.
# This strict validation prevents path traversal, URL scheme injection, or query parameter injection
# by restricting the characters allowed, thus mitigating Server-Side Request Forgery (SSRF)
# which is a common manifestation of CWE-1322 (Unrestricted Externally Accessible Runtimes)
# when an external input is used to construct a resource locator for an internal or external request.
ORDER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

@app.get('/partner/orders/{order_id}')
async def get_partner_order(order_id: str) -> dict:
    # Validate the order_id against the defined pattern.
    # If the order_id does not conform to the expected safe format,
    # a 400 Bad Request error is raised, preventing its use in the URL.
    if not ORDER_ID_PATTERN.fullmatch(order_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid order ID format. Order ID must consist of alphanumeric characters, hyphens, or underscores."
        )

    response = requests.get(
        f'https://partner.example/orders/{order_id}',
        timeout=(3, 10),
    )
    response.raise_for_status()
    return response.json()
