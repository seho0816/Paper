import math


def calculate_page_count(
    total_records: int,
    page_size: int,
) -> int:
    if page_size == 0:
        # Prevent ZeroDivisionError (CWE-369).
        # A page_size of 0 is an invalid input for pagination.
        # To avoid division by zero and provide a sensible result,
        # we treat an invalid page_size (0) effectively as 1 for the calculation.
        # If there are records, they will occupy 'total_records' pages (each with 1 item).
        # If there are no records, the count is 0 pages.
        return math.ceil(total_records / 1)
    return math.ceil(
        total_records
        / page_size
    )
