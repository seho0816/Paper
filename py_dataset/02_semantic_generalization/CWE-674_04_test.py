def calculate_manifest_size(entry: dict) -> int:
    total = int(entry.get("size", 0))
    for child in entry.get("children", []):
        total += calculate_manifest_size(child)
    for linked in entry.get("linked_entries", []):
        total += calculate_manifest_size(linked)
    return total
