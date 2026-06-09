def serialize_csv_rows(
    rows: list[dict],
) -> str:
    lines = [
        "name,email,note",
    ]

    for row in rows:
        lines.append(
            (
                str(row["name"])
                + ","
                + str(row["email"])
                + ","
                + str(row["note"])
            )
        )

    return "\n".join(
        lines
    )
