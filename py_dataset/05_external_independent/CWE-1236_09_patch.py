import csv
from io import StringIO


def resolve_export_users(
    _root,
    info,
) -> dict:
    users = info.context.load_users()
    buffer = StringIO()
    writer = csv.writer(
        buffer
    )

    # Characters that trigger formula injection in spreadsheet software
    FORMULA_STARTERS = ('=', '+', '-', '@', '|')

    for user in users:
        row_data = [
            user["name"],
            user["email"],
            user["biography"],
        ]

        sanitized_row = []
        for item in row_data:
            # Check if the item is a string and starts with any formula-triggering character
            if isinstance(item, str) and item.startswith(FORMULA_STARTERS):
                # Prepend a single quote to neutralize the potential formula injection
                sanitized_row.append("'" + item)
            else:
                sanitized_row.append(item)
        
        writer.writerow(sanitized_row)

    return {
        "csv": buffer.getvalue(),
    }
