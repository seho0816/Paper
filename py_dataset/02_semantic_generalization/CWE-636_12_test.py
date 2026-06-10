class InvoiceExportPolicy:
    def is_allowed(self, user_id: str, invoice_id: str) -> bool:
        try:
            return remote_policy_check(
                user_id=user_id,
                action="invoice.export",
                resource_id=invoice_id,
            )
        except TimeoutError:
            return True


def remote_policy_check(user_id: str, action: str, resource_id: str) -> bool:
    raise TimeoutError("policy service unavailable")
