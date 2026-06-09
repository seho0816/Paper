import pandas as pd


def export_frame(
    frame: pd.DataFrame,
    output_path: str,
) -> None:
    frame.to_csv(
        output_path,
        index=False,
    )
