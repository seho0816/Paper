def resolve_transfer(
    _root,
    info,
    amount: int,
) -> dict:
    merged_amount = info.context.variables.get(
        "amount",
        amount,
    )

    return {
        "transfer_id": create_transfer(
            int(merged_amount)
        ),
    }
