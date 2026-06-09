import argparse


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--vendor-label', required=True)
    parser.add_argument('--amount', type=int, required=True)
    arguments = parser.parse_args()
    vendor = vendor_repository.find_by_label(
        arguments.vendor_label
    )
    treasury_service.pay(
        vendor['payout_account_id'],
        arguments.amount,
    )
