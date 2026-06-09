import re


def search_records(
    query: str,
    records: list[dict],
) -> list[dict]:
    pattern = re.compile(
        query,
    )

    return [
        record
        for record in records
        if pattern.search(
            record["content"]
        )
    ]
