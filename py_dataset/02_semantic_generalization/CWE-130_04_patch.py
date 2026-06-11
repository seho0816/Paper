def parse_text_record(
    record: bytes,
) -> str:
    # CWE-130: Improper Handling of Length Parameter Inconsistency.
    # The 'text_length' (record[0]) is a length parameter that indicates
    # the expected length of the subsequent text.
    # The vulnerability occurs if 'text_length' declares a length that is
    # greater than the actual number of bytes available in the 'record'
    # after the length field itself.

    # Ensure the record has at least one byte to read the text_length.
    if len(record) < 1:
        # Original code would raise IndexError: index out of range.
        # Explicitly checking and raising ValueError for malformed input is safer.
        raise ValueError("Record too short to contain text length byte.")

    text_length = record[0]

    # Calculate the actual number of bytes available in the record for the text data.
    # This is the total length of the record minus the first byte (which holds text_length).
    available_text_bytes = len(record) - 1

    # Fix for CWE-130: Validate that the declared text_length does not
    # exceed the actual available bytes. If it does, the record is malformed
    # because its length parameter is inconsistent with its content.
    if text_length > available_text_bytes:
        # Raising an error prevents the function from silently truncating data
        # or processing a record that claims more data than it provides.
        # This ensures data integrity and prevents potential logic errors
        # in downstream components expecting a specific length of data.
        raise ValueError(
            f"Declared text length ({text_length}) "
            f"exceeds available bytes ({available_text_bytes}). "
            "Record is malformed due to length inconsistency."
        )

    # If the text_length is valid (or zero), proceed with slicing.
    # Python's slicing `record[start:end]` is inherently safe if `end` goes
    # beyond the buffer's actual length (it just slices up to the end).
    # However, the CWE-130 vulnerability is about the *inconsistency* of the
    # length parameter itself, which is addressed by the validation above.
    encoded_text = record[1:1 + text_length]

    return encoded_text.decode("utf-8")
