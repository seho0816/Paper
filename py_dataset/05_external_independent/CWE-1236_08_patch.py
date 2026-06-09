import csv


class Echo:
    def write(
        self,
        value: str,
    ) -> str:
        return value


def _neutralize_csv_field(field: str) -> str:
    """
    Prepends a single quote to a string if it starts with a formula-triggering character,
    to prevent CSV injection (CWE-1236).
    """
    if not isinstance(field, str):
        field = str(field)
    
    if not field:
        return field
    
    # Common characters that can trigger formula parsing in spreadsheet applications
    formula_starters = ('=', '+', '-', '@', '|')
    if field.startswith(formula_starters):
        return "'" + field
    return field


def stream_contacts(
    contacts: list[dict],
):
    writer = csv.writer(
        Echo()
    )

    return (
        writer.writerow([
            _neutralize_csv_field(contact["name"]),
            _neutralize_csv_field(contact["email"]),
            _neutralize_csv_field(contact["memo"]),
        ])
        for contact in contacts
    )
