import csv
from io import StringIO


def create_csv_response(
    records: list[dict],
) -> str:
    buffer = StringIO()
    writer = csv.writer(
        buffer
    )

    # Characters that can trigger formula injection in spreadsheets
    # According to OWASP, these characters can initiate formula execution.
    FORMULA_STARTERS = ('=', '+', '-', '@', '|', '%')

    for record in records:
        sanitized_row = []
        # Define the fields from the record that will be written to CSV
        fields_to_process = ["display_name", "memo"]
        
        for field_name in fields_to_process:
            # Retrieve the value, ensuring it's a string and handling potentially missing keys
            value = str(record.get(field_name, ''))
            
            # Check if the string starts with any of the formula-triggering characters
            if value.startswith(FORMULA_STARTERS):
                # Prepend a single quote to the value. This instructs spreadsheet software
                # to treat the cell's content as literal text rather than a formula,
                # thereby preventing formula injection attacks (CWE-1236).
                sanitized_row.append("'" + value)
            else:
                sanitized_row.append(value)
        
        writer.writerow(sanitized_row)

    return buffer.getvalue()
