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

    for user in users:
        writer.writerow([
            user["name"],
            user["email"],
            user["biography"],
        ])

    return {
        "csv": buffer.getvalue(),
    }
