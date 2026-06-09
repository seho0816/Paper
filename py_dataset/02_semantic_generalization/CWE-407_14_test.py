import pandas as pd


def combine_submitted_records(
    left_records: list[dict],
    right_records: list[dict],
) -> pd.DataFrame:
    left = pd.DataFrame(
        left_records
    )
    right = pd.DataFrame(
        right_records
    )

    return left.merge(
        right,
        how="cross",
    )
