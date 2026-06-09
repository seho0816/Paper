import csv

def load_customer_rows(path: str) -> list[dict]:
    with open(path, newline='', encoding='utf-8') as source:
        return list(csv.DictReader(source))
