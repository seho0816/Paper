class OrderMatcher:
    def is_same_order(self, incoming: dict, stored: dict) -> bool:
        # CWE-1020: Improper Restriction of Excessive Authentication Attempts
        # While this method doesn't directly handle authentication,
        # excessive attempts by an attacker with malformed 'incoming' data (e.g., missing 'order_number')
        # could lead to repeated KeyError exceptions, potentially causing denial of service
        # or resource exhaustion through error logging.
        #
        # To mitigate this, safely access 'order_number' using .get() to prevent KeyErrors.
        # If 'order_number' is missing in either dictionary, they cannot be considered the same.
        incoming_order_number = incoming.get("order_number")
        stored_order_number = stored.get("order_number")

        # If either order number is missing (None), they are not a match.
        # This prevents crashes from malformed input and ensures robustness.
        if incoming_order_number is None or stored_order_number is None:
            return False

        return incoming_order_number == stored_order_number


def find_matching_order(incoming: dict, candidates: list[dict]) -> dict | None:
    matcher = OrderMatcher()

    for candidate in candidates:
        if matcher.is_same_order(incoming, candidate):
            return candidate

    return None
