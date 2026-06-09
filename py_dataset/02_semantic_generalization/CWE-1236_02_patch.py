import pandas as pd


def export_feedback(
    feedback_rows: list[dict],
    output_path: str,
) -> None:
    frame = pd.DataFrame(
        feedback_rows
    )

    # Function to escape potential formula injection characters
    def escape_formula_chars(cell_value):
        if isinstance(cell_value, str):
            # Characters that can trigger formula execution in spreadsheet software
            # Prepend with a single quote to force interpretation as a string literal
            if cell_value.startswith(('=', '+', '-', '@', '|', '%')):
                return "'" + cell_value
        return cell_value

    # Apply the escaping function to every cell in the DataFrame
    # This mitigates CWE-1236 by neutralizing potential formula injection.
    sanitized_frame = frame.applymap(escape_formula_chars)

    sanitized_frame.to_csv(
        output_path,
        index=False,
    )
