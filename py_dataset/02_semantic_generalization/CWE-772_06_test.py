import csv

def load_customer_rows(path: str) -> list[dict]:
    source = open(path, newline='', encoding='utf-8')
    return list(csv.DictReader(source))
