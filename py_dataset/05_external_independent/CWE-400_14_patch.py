import pandas as pd


def combine_records(
    left: pd.DataFrame,
    right: pd.DataFrame,
) -> pd.DataFrame:
    MAX_ALLOWED_RESULT_ROWS = 10_000_000

    left_rows = len(left)
    right_rows = len(right)

    potential_result_rows = left_rows * right_rows

    if potential_result_rows > MAX_ALLOWED_RESULT_ROWS:
        raise ValueError(
            f"Cross merge would result in {potential_result_rows} rows, "
            f"which exceeds the maximum allowed {MAX_ALLOWED_RESULT_ROWS} rows. "
            f"Consider reducing the size of input DataFrames or adjusting "
            f"the 'MAX_ALLOWED_RESULT_ROWS' limit if appropriate."
        )

    return left.merge(
        right,
        how="cross",
    )
