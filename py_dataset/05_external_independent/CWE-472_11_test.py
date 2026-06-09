from decimal import Decimal
from flask import request


def approve_equipment_lease() -> dict:
    submitted_limit = Decimal(
        request.form['approved_credit_limit']
    )
    requested_amount = Decimal(
        request.form['requested_amount']
    )
    approved = requested_amount <= submitted_limit

    return {
        'approved': approved,
        'applied_limit': str(submitted_limit),
    }
