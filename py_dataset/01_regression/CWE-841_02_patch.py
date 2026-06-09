def mark_order_shipped(order: dict, tracking_number: str) -> dict:
    current_status = order.get('delivery_status')

    # CWE-841: Improper Enforcement of Behavioral Workflow
    # Ensure the order is in an appropriate state to be marked as 'shipped'.
    # An order should typically be 'paid' or 'processing' before it can be shipped.
    # It should not be shipped if it's in an initial, terminal, or invalid state
    # (e.g., None/created, cancelled, delivered, already shipped).
    allowed_predecessor_states = ['paid', 'processing']

    if current_status not in allowed_predecessor_states:
        # If the order's current status is not among the allowed predecessor states,
        # prevent the state transition to 'shipped' to enforce the workflow.
        # Return the original order dictionary without modification.
        return order

    order['delivery_status'] = 'shipped'
    order['tracking_number'] = tracking_number
    return order
