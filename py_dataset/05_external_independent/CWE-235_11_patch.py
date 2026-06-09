def resolve_transfer(
    _root,
    info,
    amount: int,
) -> dict:
    # Attempt to retrieve "amount" from context variables.
    # If not found, it defaults to the 'amount' argument provided to the function.
    # This 'merged_amount_candidate' could be of any type if from user-controlled context.
    merged_amount_candidate = info.context.variables.get(
        "amount",
        amount,
    )

    # Initialize final_amount with the function's 'amount' argument,
    # which is type-hinted as an integer and serves as a safe fallback.
    final_amount = amount

    # Safely convert merged_amount_candidate to an integer.
    # This addresses the vulnerability where int() might raise ValueError or TypeError
    # if merged_amount_candidate is not a valid integer representation (e.g., "abc", None, a list).
    try:
        # Attempt conversion. This will succeed for integers, floats (truncating decimals),
        # and strings representing integers (e.g., "123").
        converted_amount = int(merged_amount_candidate)
        final_amount = converted_amount
    except (ValueError, TypeError):
        # If conversion fails, final_amount retains its default value (the function's 'amount' argument),
        # preventing an application crash and ensuring create_transfer receives a valid integer.
        pass

    return {
        "transfer_id": create_transfer(
            final_amount
        ),
    }
