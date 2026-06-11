import math

def resolve_resource(
    raw_resource_id: str,
) -> dict:
    try:
        # Attempt to convert the raw_resource_id to a float first,
        # as per the original logic, which implies truncation of decimals
        # (e.g., "123.45" -> 123).
        temp_float = float(raw_resource_id)

        # CWE-704: Improper Type Conversion.
        # The original code would raise an OverflowError for 'inf'
        # and a ValueError for 'nan' when int() is called on them.
        # This explicit check prevents these unhandled exceptions,
        # which could otherwise lead to denial of service or unexpected behavior.
        if math.isinf(temp_float) or math.isnan(temp_float):
            raise ValueError(f"Resource ID cannot be infinite or NaN: {raw_resource_id}")

        # Convert the float to an integer (truncating decimals) and then to a string.
        normalized_id = str(int(temp_float))
    except (ValueError, OverflowError) as e:
        # Catch all errors that may occur during the float() or int() conversion
        # (e.g., non-numeric strings, values too large for int).
        # Re-raising a ValueError ensures that invalid inputs are handled gracefully
        # by the caller, preventing application crashes due to improper input types.
        raise ValueError(f"Invalid numeric resource ID format: {raw_resource_id}. Details: {e}") from e

    # resource_store is assumed to be available in the current scope as per the original code.
    return resource_store[
        normalized_id
    ]
