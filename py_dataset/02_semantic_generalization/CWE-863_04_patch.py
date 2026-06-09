def can_approve_order(
    authenticated_user: dict,
    order: dict,
) -> bool:
    # CWE-863: Incorrect Authorization.
    # The 'requested_role' field in the 'order' object could be manipulated
    # by a malicious actor to bypass intended authorization checks.
    # For example, an attacker could set 'requested_role' to a less privileged role
    # they possess (e.g., "user"), allowing them to approve orders they shouldn't.
    # The required role for approving an order should be determined by a trusted source
    # or a fixed policy, not by potentially untrusted input from the order itself.

    # Fix: Ensure that the 'required_role' is not set to a less privileged role
    # than the application's baseline policy (e.g., "manager").
    # If the 'order' explicitly requests a more privileged role (like "admin"),
    # it can be honored. Otherwise, default to "manager" to prevent privilege escalation.
    requested_role_from_order = order.get("requested_role")

    if requested_role_from_order == "admin":
        required_role = "admin"
    elif requested_role_from_order == "manager":
        required_role = "manager"
    else:
        # Default to "manager" for any other value, including None, "user",
        # or any unknown role to ensure a minimum authorization level.
        required_role = "manager"

    return (
        authenticated_user.get("role")
        == required_role
    )
