def release_marketplace_payout(storefront_name: str, payout_id: str) -> None:
    seller = seller_directory.find_by_storefront_name(
        storefront_name
    )
    payout_repository.release_to_seller(
        payout_id,
        seller['seller_id'],
    )
