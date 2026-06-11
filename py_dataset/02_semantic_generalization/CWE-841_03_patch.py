def activate_seller_payout(seller: dict) -> dict:
    updated_seller = seller.copy()
    updated_seller['payout_status'] = 'enabled'
    updated_seller['can_receive_funds'] = True
    return updated_seller
