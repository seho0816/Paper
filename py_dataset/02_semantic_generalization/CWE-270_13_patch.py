security_context = {
    "principal_id": None,
    "role": "anonymous",
}


class SupportImpersonationService:
    def rebuild_customer_index(self, customer_id: str) -> None:
        # Store the original security context to ensure it's restored later.
        original_principal_id = security_context["principal_id"]
        original_role = security_context["role"]

        try:
            # Elevate privileges for the specific operation.
            security_context["principal_id"] = customer_id
            security_context["role"] = "administrator"

            rebuild_index_for_customer(customer_id)
        finally:
            # Restore the original security context to prevent privilege escalation
            # for subsequent operations, even if an error occurred.
            security_context["principal_id"] = original_principal_id
            security_context["role"] = original_role


def rebuild_index_for_customer(customer_id: str) -> None:
    print(customer_id, security_context["role"])
