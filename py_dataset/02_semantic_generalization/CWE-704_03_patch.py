def load_account(
    raw_account_id: str,
) -> dict:
    # CWE-704: Improper Control of Generation of Code ('Code Injection')
    # The original code `int(float(raw_account_id))` allows non-integer string formats
    # (e.g., "123.45", "1.23e2") to be converted into an integer by first converting
    # to float, which truncates decimal parts or handles scientific notation.
    # This is an "improper control" over how the `account_id` is generated from
    # user input, as it can lead to an unintended numeric value being used.
    # For example, "123.99" would become `123`. If `123.99` is expected to be
    # an invalid ID, but `123` is a valid one, this could bypass validation
    # or lead to unintended account access.
    #
    # The fix is to directly convert `raw_account_id` to an integer using `int()`.
    # This ensures that only strictly integer-formatted strings are accepted,
    # raising a ValueError for any input that is not a valid integer representation
    # (e.g., "123.45", "1.23e2", non-numeric strings). This provides strict control
    # over the generated `account_id` value, preventing unexpected numeric
    # interpretations or truncations that could lead to logic flaws.
    account_id = int(raw_account_id)

    return account_repository.find(
        account_id,
    )
