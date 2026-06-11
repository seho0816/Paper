def update_order_status(order: dict, new_status: str) -> dict:
    allowed_statuses = {'paid', 'cancelled', 'shipped'}
    if new_status not in allowed_statuses:
        raise ValueError(f"Invalid status '{new_status}'. Allowed statuses are: {', '.join(allowed_statuses)}")
    order['status'] = new_status
    return order
