def find_duplicate_rows(
    rows: list[dict],
) -> list[
    tuple[int, int]
]:
    duplicates = []
    # To address the CWE-407 'Algorithm Simplification' leading to inefficient comparison
    # (quadratic time complexity), we use a hash-based approach.
    # This stores normalized rows and their corresponding original indices,
    # reducing the time complexity from O(N^2 * C) to O(N * C + N) (average case),
    # where C is the complexity of normalize_row.
    normalized_to_indices = {}

    for index, row in enumerate(rows):
        # normalize_row is assumed to be defined elsewhere and return a hashable type.
        normalized_row = normalize_row(row)
        if normalized_row not in normalized_to_indices:
            normalized_to_indices[normalized_row] = []
        normalized_to_indices[normalized_row].append(index)

    # After grouping, iterate through the lists of indices to find duplicate pairs
    for indices_list in normalized_to_indices.values():
        if len(indices_list) > 1:
            # If a normalized_row corresponds to multiple original indices,
            # these original rows are duplicates.
            # Generate all unique pairs (i, j) where i < j from this list.
            for i in range(len(indices_list)):
                for j in range(i + 1, len(indices_list)):
                    duplicates.append(
                        (
                            indices_list[i],
                            indices_list[j],
                        )
                    )

    return duplicates
