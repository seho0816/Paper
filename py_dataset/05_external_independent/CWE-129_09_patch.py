import numpy as np


def read_measurement(
    values: np.ndarray,
    index_text: str,
) -> float:
    index = int(
        index_text
    )

    # CWE-129: Validate index to prevent out-of-bounds access
    if not (0 <= index < len(values)):
        raise IndexError(f"Index {index} is out of bounds for array of size {len(values)}")

    return float(
        values[index]
    )
