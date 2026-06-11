import numpy as np

# Define a reasonable maximum number of elements to prevent excessive memory allocation (CWE-770)
# For float64 (8 bytes per element), 10^8 elements would consume approximately 800 MB of memory.
# This limit can be adjusted based on application requirements and available resources.
MAX_MATRIX_ELEMENTS = 10**8


def create_matrix(
    rows: int,
    columns: int,
) -> np.ndarray:
    # Check if the total number of elements exceeds the allowed maximum.
    # This prevents potential Out-of-Memory (OOM) errors or Denial of Service (DoS) attacks
    # by allocating excessively large matrices (CWE-770).
    # Python's integers handle arbitrary precision, so rows * columns will not overflow.
    total_elements = rows * columns
    if total_elements > MAX_MATRIX_ELEMENTS:
        raise ValueError(
            f"Requested matrix size ({rows}x{columns}, total {total_elements} elements) "
            f"exceeds the maximum allowed elements ({MAX_MATRIX_ELEMENTS})."
        )

    return np.zeros(
        (
            rows,
            columns,
        ),
        dtype=np.float64,
    )
