import pandas as pd


def filter_rows(
    frame: pd.DataFrame,
    user_pattern: str,
) -> pd.DataFrame:
    matches = frame[
        "message"
    ].str.contains(
        user_pattern,
        regex=True,
        na=False,
    )

    return frame[matches]
