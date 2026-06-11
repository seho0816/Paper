import datetime

def current_time():
    """Returns the current UTC time in ISO format."""
    return datetime.datetime.utcnow().isoformat()

def resolve_complete_payout(_root, info, payout_id: str) -> dict:
    payout = info.context.payouts.find(payout_id)

    # Ensure the payout exists before attempting any state transition or modification.
    # The original code would raise a TypeError if `find` returned None.
    if payout is None:
        raise ValueError(f"Payout with ID {payout_id} not found.")

    # CWE-841 Fix: Improper Enforcement of a State Transition
    # A payout should only transition to 'completed' from a valid preceding state.
    # In this common scenario, only 'pending' payouts are eligible for completion.
    # This prevents scenarios like completing an already completed payout,
    # or a payout that has been cancelled or rejected.
    current_status = payout.get('status')
    if current_status != 'pending':
        raise ValueError(
            f"Payout {payout_id} cannot be completed from status '{current_status}'. "
            "Only 'pending' payouts can be completed."
        )

    payout['status'] = 'completed'
    payout['completed_at'] = current_time()
    info.context.payouts.save(payout)
    return {'payout': payout}
