import numpy as np


def read_measurement(
    values: np.ndarray,
    index_text: str,
) -> float:
    index = int(
        index_text
    )

    return float(
        values[index]
    )
