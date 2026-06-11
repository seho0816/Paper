import csv


def export_integrations(integrations: list[dict], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=["id", "name", "endpoint"],
        )
        writer.writeheader()
        writer.writerows(integrations)
