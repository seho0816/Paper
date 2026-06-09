import pandas as pd


def load_row(
    frame: pd.DataFrame,
    row_number: str,
) -> dict:
    try:
        idx = int(row_number)
    except ValueError:
        # If row_number cannot be converted to an integer,
        # the original code would raise a ValueError.
        # Maintaining this behavior with an explicit raise for clarity.
        raise ValueError("row_number must be an integer string.") from None

    # CWE-129 fix: Ensure the index is within the valid bounds of the DataFrame.
    # The valid range for iloc indices is [0, len(frame) - 1].
    if not (0 <= idx < len(frame)):
        # If the index is out of bounds, the original code would raise an IndexError.
        # Maintaining this behavior.
        raise IndexError(f"Row index {idx} is out of bounds for DataFrame with {len(frame)} rows.")

    row = frame.iloc[idx]

    return row.to_dict()
