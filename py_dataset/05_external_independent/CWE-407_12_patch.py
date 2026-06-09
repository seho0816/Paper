def resolve_find_duplicates(
    _root,
    _info,
    rows: list[dict],
) -> dict:
    duplicates = []
    # This dictionary will store normalized row values as keys
    # and a list of indices where they appeared as values.
    # Example: { normalized_value_A: [index_of_A1, index_of_A2, ...], ... }
    seen_normalized_rows = {}

    for current_index, current_row in enumerate(rows):
        # We assume normalize_row is an existing function that takes a dict and returns a hashable value.
        # The performance bottleneck (CWE-407) is in the O(N^2) comparison loop for potentially expensive
        # normalized data representations, leading to uncontrolled resource consumption.
        # By using a hash map, the complexity is reduced to O(N) on average.
        normalized_current_row = normalize_row(current_row)

        if normalized_current_row in seen_normalized_rows:
            # If this normalized row value has been encountered before,
            # then every previous occurrence is a duplicate of the current row.
            for prev_index in seen_normalized_rows[normalized_current_row]:
                # Add the pair [previous_index, current_index] to duplicates.
                # Since current_index is always greater than prev_index,
                # the order (left_index < right_index) is naturally maintained.
                duplicates.append([
                    prev_index,
                    current_index,
                ])
            # After finding all pairs with previous occurrences,
            # add the current_index to the list for this normalized value
            seen_normalized_rows[normalized_current_row].append(current_index)
        else:
            # If this is the first time seeing this normalized row value,
            # initialize its entry in the dictionary with the current index.
            seen_normalized_rows[normalized_current_row] = [current_index]

    return {
        "duplicates": duplicates,
    }
