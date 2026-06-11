import os
from decimal import Decimal
from flask import request


def approve_equipment_lease() -> dict:
    # CWE-472: External Control of Assumed-Immutable Web Content
    # The 'approved_credit_limit' should be a server-controlled value,
    # not directly supplied by the client via request.form, as this allows
    # an attacker to manipulate their approved limit.
    # To fix this, the 'submitted_limit' is now sourced from a trusted
    # server-side environment variable. This ensures the limit is immutable
    # from the client's perspective and controlled by the server's configuration.
    submitted_limit = Decimal(
        os.environ["APPROVED_CREDIT_LIMIT_SERVER_SIDE"]
    )
    requested_amount = Decimal(
        request.form['requested_amount']
    )
    approved = requested_amount <= submitted_limit

    return {
        'approved': approved,
        'applied_limit': str(submitted_limit),
    }
