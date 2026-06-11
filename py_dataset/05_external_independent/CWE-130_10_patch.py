def parse_length_delimited_field(
    payload: bytes,
) -> bytes:
    field_length = payload[0]

    # CWE-130: Improper Handling of Length Parameter Inconsistency
    # Ensure that the slice operation does not attempt to read beyond the
    # actual bounds of the payload, even if the declared field_length is larger
    # than the available data.
    start_index = 1
    # The maximum index (exclusive) we can slice up to is the length of the payload.
    max_possible_end_index = len(payload)
    # The desired end index based on the field_length.
    desired_end_index = start_index + field_length
    
    # Take the minimum of the desired end index and the maximum possible end index
    # to prevent out-of-bounds access and ensure consistency with available data.
    actual_end_index = min(desired_end_index, max_possible_end_index)

    return payload[
        start_index:actual_end_index
    ]
