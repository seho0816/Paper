import csv
import io

def serialize_csv_rows(
    rows: list[dict],
) -> str:
    # CWE-1236: Improper Neutralization of Formula Elements in a CSV File
    # To mitigate formula injection, prepend an apostrophe to any field
    # that starts with a formula-triggering character.
    FORMULA_TRIGGERS = ('=', '+', '-', '@', '|', '%')

    # Use an in-memory text buffer to write CSV data
    output_buffer = io.StringIO()
    
    # Create a CSV writer.
    # The csv module handles standard CSV escaping (e.g., quoting fields with commas or newlines).
    # csv.QUOTE_MINIMAL means fields will only be quoted if they contain special characters.
    writer = csv.writer(output_buffer, quoting=csv.QUOTE_MINIMAL)

    # Define the header row based on the expected keys and their order.
    header = ["name", "email", "note"]
    writer.writerow(header)

    for row in rows:
        processed_row_data = []
        for key in header:
            # Ensure the value is a string, consistent with the original code's str() conversion.
            # This assumes 'name', 'email', 'note' keys are always present in each dict.
            value_str = str(row[key])
            
            # Apply formula injection neutralization:
            # If the string starts with a formula trigger, prepend an apostrophe.
            # This forces spreadsheet software to interpret the cell content as a string literal.
            if value_str.startswith(FORMULA_TRIGGERS):
                processed_row_data.append("'" + value_str)
            else:
                processed_row_data.append(value_str)
        
        writer.writerow(processed_row_data)

    # Return the entire CSV content as a single string.
    return output_buffer.getvalue()
