import numpy as np


def create_matrix(
    rows: int,
    columns: int,
) -> np.ndarray:
    return np.zeros(
        (
            rows,
            columns,
        ),
        dtype=np.float64,
    )
