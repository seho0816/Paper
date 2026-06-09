row_pool: list[list[dict]] = []


def build_visible_rows(records: list[dict]) -> list[dict]:
    # CWE-226: Information Exposure.
    # The original code might reuse a list from 'row_pool' that
    # could potentially contain sensitive data from a previous context,
    # leading to information exposure.
    # To fix this, we ensure 'rows' always starts as a fresh, empty list
    # for each call, preventing any data leakage from the 'row_pool'.
    rows = []
    rows.extend(
        {"id": record["id"], "name": record["name"]}
        for record in records
    )
    return rows
