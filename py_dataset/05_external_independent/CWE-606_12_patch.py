MAX_COPIES_LIMIT = 100  # Define a reasonable upper limit for the number of copies

def resolve_duplicate_export(_root, _info, export_id: str, copies: int) -> dict:
    # CWE-606: Unchecked Input for Loop Condition
    # Validate the 'copies' parameter to prevent resource exhaustion due to excessively large loops.
    if not isinstance(copies, int) or copies <= 0 or copies > MAX_COPIES_LIMIT:
        raise ValueError(
            f"Invalid number of copies. Must be a positive integer not exceeding {MAX_COPIES_LIMIT}."
        )

    generated = []
    for sequence in range(copies):
        # Assuming 'export_service' is an external dependency available in the scope.
        # Its internal implementation security is outside the scope of this specific CWE fix.
        generated.append(export_service.clone(export_id, sequence))
    return {'exports': generated}
