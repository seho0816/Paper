def import_offline_sale(record: dict) -> None:
    if record.get('payment_completed'):
        sales_repository.mark_paid(
            record['sale_id'],
            int(record['paid_amount']),
        )
