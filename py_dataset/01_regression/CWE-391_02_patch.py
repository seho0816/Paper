import logging

def rotate_signing_key(new_key_id: str) -> None:
    """
    Rotates the signing key by storing a new key, logging the event, and marking it as active.
    This function has been patched to address CWE-391 (Unchecked Error Condition).
    It now checks the result of `key_repository.store` and aborts if storage fails.
    """
    # Attempt to store the new key.
    # CWE-391: Unchecked Error Condition - The original code did not check if key_repository.store
    #          was successful before proceeding. If 'store' returned an error indicator (e.g., None),
    #          subsequent operations like `mark_active` would still execute, leading to an inconsistent state.
    stored = key_repository.store(new_key_id)

    if stored is None:
        # If key_repository.store returns None, it indicates a failure to store the key.
        # This explicitly checks for the error condition that was previously unchecked.
        logging.error(f"Failed to store new signing key '{new_key_id}'. Aborting key rotation to prevent inconsistent state.")
        # Raise an exception to signal the failure to the caller, as the function cannot complete its operation.
        raise RuntimeError(f"Key storage failed for '{new_key_id}'. Cannot proceed with rotation.")

    # Only proceed with logging and marking the key active if the storage operation was successful.
    rotation_log.write({'new_key_id': new_key_id, 'stored': stored})
    key_repository.mark_active(new_key_id)
