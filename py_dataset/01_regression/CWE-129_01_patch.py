def select_token_candidate(
    candidates: list[str],
    requested_index: int,
) -> str:
    # CWE-129: Improper Neutralization of Special Elements in an Array Index
    # Ensure the requested_index is within the valid bounds of the candidates list
    # to prevent out-of-bounds access.
    if not (0 <= requested_index < len(candidates)):
        # While the original code would raise an IndexError naturally for out-of-bounds access,
        # explicitly checking the bounds and raising the error makes the vulnerability mitigation
        # clear and prevents potential unexpected behavior or application crashes
        # if the IndexErrors were not robustly handled elsewhere, addressing DoS concerns.
        raise IndexError(f"Index {requested_index} is out of bounds for candidates list of size {len(candidates)}")
    return candidates[
        requested_index
    ]
