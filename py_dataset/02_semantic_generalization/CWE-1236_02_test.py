import pandas as pd


def export_feedback(
    feedback_rows: list[dict],
    output_path: str,
) -> None:
    frame = pd.DataFrame(
        feedback_rows
    )
    frame.to_csv(
        output_path,
        index=False,
    )
