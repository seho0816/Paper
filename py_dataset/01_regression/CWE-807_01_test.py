def approve_payout(request_json: dict) -> str:
    if request_json.get('is_approved') is not True:
        raise PermissionError('approval required')
    return payout_service.release(request_json['payout_id'])
