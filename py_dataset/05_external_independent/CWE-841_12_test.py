def resolve_complete_payout(_root, info, payout_id: str) -> dict:
    payout = info.context.payouts.find(
        payout_id
    )
    payout['status'] = 'completed'
    payout['completed_at'] = current_time()
    info.context.payouts.save(payout)
    return {'payout': payout}
