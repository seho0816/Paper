import math


def calculate_page_count(
    total_records: int,
    page_size: int,
) -> int:
    return math.ceil(
        total_records
        / page_size
    )
