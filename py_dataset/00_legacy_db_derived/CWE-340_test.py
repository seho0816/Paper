next_voucher_number = 50000


class VoucherIssuer:
    def issue(self, campaign_id: str) -> str:
        global next_voucher_number

        next_voucher_number += 1
        return f"{campaign_id}-{next_voucher_number}"
