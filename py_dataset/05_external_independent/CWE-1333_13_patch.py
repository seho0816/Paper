import re
import concurrent.futures


def search_records(
    query: str,
    records: list[dict],
) -> list[dict]:
    pattern = re.compile(
        query,
    )

    results = []
    search_timeout_seconds = 0.1

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        for record in records:
            future = executor.submit(pattern.search, record["content"])
            try:
                match = future.result(timeout=search_timeout_seconds)
                if match:
                    results.append(record)
            except concurrent.futures.TimeoutError:
                pass
    return results
