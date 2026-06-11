import csv


def export_tickets(
    tickets: list[dict],
    output_path: str,
) -> None:
    formula_starters = ('=', '+', '-', '@')

    sanitized_tickets = []
    for ticket in tickets:
        sanitized_ticket = {}
        for key, value in ticket.items():
            # Check if the value is a string and starts with a formula character
            if isinstance(value, str) and value.startswith(formula_starters):
                # Prepend a single quote to neutralize potential formula injection
                sanitized_ticket[key] = "'" + value
            else:
                sanitized_ticket[key] = value
        sanitized_tickets.append(sanitized_ticket)

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
            sanitized_tickets
        )
