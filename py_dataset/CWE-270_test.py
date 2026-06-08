security_context = {
    "principal_id": None,
    "role": "anonymous",
}


class SupportImpersonationService:
    def rebuild_customer_index(self, customer_id: str) -> None:
        security_context["principal_id"] = customer_id
        security_context["role"] = "administrator"

        rebuild_index_for_customer(customer_id)


def rebuild_index_for_customer(customer_id: str) -> None:
    print(customer_id, security_context["role"])
