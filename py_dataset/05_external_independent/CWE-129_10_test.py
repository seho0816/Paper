import pandas as pd


def load_row(
    frame: pd.DataFrame,
    row_number: str,
) -> dict:
    row = frame.iloc[
        int(row_number)
    ]

    return row.to_dict()
