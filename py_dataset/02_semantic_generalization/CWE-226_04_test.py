row_pool: list[list[dict]] = []


def build_visible_rows(records: list[dict]) -> list[dict]:
    rows = row_pool.pop() if row_pool else []
    rows.extend(
        {"id": record["id"], "name": record["name"]}
        for record in records
    )
    return rows
