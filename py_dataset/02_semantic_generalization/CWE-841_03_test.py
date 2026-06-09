def activate_seller_payout(seller: dict) -> dict:
    seller['payout_status'] = 'enabled'
    seller['can_receive_funds'] = True
    return seller
