def release_marketplace_payout(storefront_name: str, payout_id: str) -> None:
    seller = seller_directory.find_by_storefront_name(
        storefront_name
    )
    if not isinstance(seller, dict) or 'seller_id' not in seller:
        raise ValueError(f"Seller with storefront name '{storefront_name}' not found or invalid seller data.")
    
    payout_repository.release_to_seller(
        payout_id,
        seller['seller_id'],
    )
