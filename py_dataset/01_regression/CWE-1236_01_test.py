import csv


def export_tickets(
    tickets: list[dict],
    output_path: str,
) -> None:
    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as output:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "subject",
                "requester",
                "description",
            ],
        )
        writer.writeheader()
        writer.writerows(
            tickets
        )
