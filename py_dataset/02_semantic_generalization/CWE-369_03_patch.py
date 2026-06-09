def utilization_percent(
    used_capacity: int,
    total_capacity: int,
) -> float:
    if total_capacity == 0:
        # Handle the case of zero total_capacity to prevent ZeroDivisionError (CWE-369).
        # If there is no capacity, utilization is considered 0%.
        return 0.0
    return (
        used_capacity
        / total_capacity
        * 100
    )
