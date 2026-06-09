def persist_export(
    destination: str,
    content: bytes,
) -> str:
    # CWE-252: The return value of `storage_client.put` is unchecked.
    # If `storage_client.put` fails (e.g., by returning False or an error object
    # that evaluates to False), the function would still return `destination`,
    # falsely indicating success. This fix assumes `storage_client.put`
    # returns a truthy value on success and a falsy value on failure,
    # or raises an exception on failure.
    # The most robust fix for an operation that might fail and prevent
    # a successful outcome (like returning 'destination') is to raise an exception.
    result = storage_client.put(
        destination,
        content,
    )
    if not result:
        # If the put operation explicitly indicates failure (e.g., returns False or None),
        # raise an exception to prevent misleading the caller.
        raise RuntimeError(f"Failed to persist export to {destination}: Storage client reported failure.")
    return destination
