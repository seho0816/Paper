import pandas as pd


def combine_records(
    left: pd.DataFrame,
    right: pd.DataFrame,
) -> pd.DataFrame:
    return left.merge(
        right,
        how="cross",
    )
