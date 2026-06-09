def reserve_product(request_json: dict) -> bool:
    # The vulnerability CWE-602 is "Client-Side Enforcement of Server-Side Security".
    # The original code relied on 'inventory_available' provided by the client,
    # which an attacker could manipulate to bypass server-side inventory checks.
    # The server must make its own security decisions, not trust client input for them.

    # FIX: Remove the reliance on client-provided 'inventory_available'.
    # It is assumed that 'inventory_repository.reserve' is a robust server-side method
    # that independently verifies inventory availability and handles reservation logic
    # (e.g., by ensuring sufficient stock, raising an exception on failure, or otherwise
    # preventing invalid reservations). This ensures the security decision is made
    # server-side, not enforced by the client.

    # Original vulnerable line removed:
    # if not request_json.get('inventory_available'):
    #     return False

    # The server now proceeds directly to attempt the reservation, relying on
    # inventory_repository.reserve to perform all necessary server-side validations.
    inventory_repository.reserve(
        request_json['sku'],
        int(request_json['quantity']),
    )
    return True
