def utilization_percent(
    used_capacity: int,
    total_capacity: int,
) -> float:
    return (
        used_capacity
        / total_capacity
        * 100
    )
