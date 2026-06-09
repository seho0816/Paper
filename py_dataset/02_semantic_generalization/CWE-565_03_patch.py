def list_tenant_orders(cookies: dict) -> list[dict]:
    # CWE-565: Improper Privilege Management.
    # The 'tenant_id' should not be taken directly from client-controlled cookies,
    # as an attacker could manipulate this to access data of other tenants (horizontal privilege escalation).
    #
    # The fix involves obtaining the 'tenant_id' from a trusted, server-side
    # authentication/session management system that guarantees the identity of the authenticated user.
    # We assume an 'auth_manager' object is available in the global scope (similar to 'order_repository')
    # and provides a method to securely retrieve the authenticated user's tenant ID.
    tenant_id = auth_manager.get_authenticated_tenant_id()
    return order_repository.find_by_tenant(tenant_id)
