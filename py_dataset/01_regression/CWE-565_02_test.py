def delete_customer(cookies: dict, customer_id: str) -> None:
    if cookies.get("is_admin") != "true":
        raise PermissionError("administrator required")
    customer_repository.delete(customer_id)
