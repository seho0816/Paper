def calculate_manifest_size(entry: dict) -> int:
    def _calculate_manifest_size_recursive(current_entry: dict, visited_ids: set) -> int:
        # Ensure the current_entry is a dictionary before processing.
        # This prevents errors if 'children' or 'linked_entries' contain non-dict items.
        if not isinstance(current_entry, dict):
            return 0

        # Use the object's identity to track visited dictionary instances.
        # This prevents infinite recursion in case of circular references (CWE-674).
        entry_identity = id(current_entry)
        if entry_identity in visited_ids:
            return 0  # Already visited in this recursion path, return 0 to prevent cycle and double counting.

        visited_ids.add(entry_identity)

        total = int(current_entry.get("size", 0))

        for child in current_entry.get("children", []):
            total += _calculate_manifest_size_recursive(child, visited_ids)

        for linked in current_entry.get("linked_entries", []):
            total += _calculate_manifest_size_recursive(linked, visited_ids)

        return total

    # Initialize a set to keep track of visited entry identities for the top-level call.
    # This set will be passed down through all recursive calls within this calculation.
    initial_visited_ids = set()
    return _calculate_manifest_size_recursive(entry, initial_visited_ids)
