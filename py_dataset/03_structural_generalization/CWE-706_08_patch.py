import argparse


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--vendor-label', required=True)
    parser.add_argument('--amount', type=int, required=True)
    arguments = parser.parse_args()
    vendor = vendor_repository.find_by_label(
        arguments.vendor_label
    )
    
    # CWE-706: Improper Neutralization of Special Elements in Output (or other context).
    # In this context, if `find_by_label` returns None (indicating no vendor found),
    # attempting to access `vendor['payout_account_id']` would lead to a TypeError,
    # conceptually equivalent to dereferencing a null pointer or accessing an invalid object.
    # This check ensures that a valid vendor object is present before attempting to access its properties.
    if vendor is None:
        raise ValueError(f"Vendor with label '{arguments.vendor_label}' not found.")

    treasury_service.pay(
        vendor['payout_account_id'],
        arguments.amount,
    )
