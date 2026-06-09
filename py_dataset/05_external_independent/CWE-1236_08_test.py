import csv


class Echo:
    def write(
        self,
        value: str,
    ) -> str:
        return value


def stream_contacts(
    contacts: list[dict],
):
    writer = csv.writer(
        Echo()
    )

    return (
        writer.writerow([
            contact["name"],
            contact["email"],
            contact["memo"],
        ])
        for contact in contacts
    )
