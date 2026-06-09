import threading


request_identity = threading.local()


# Assume customer_repository is available in the scope where this function is called.
# The original code did not define customer_repository, so we will not add it here.
# For example, it might be an instance of a class like this:
# class CustomerRepository:
#     def load_sensitive_profile(self, customer_id: str) -> dict:
#         # ... implementation ...
#         pass
# customer_repository = CustomerRepository()


def inspect_customer_as_support(customer_id: str) -> dict:
    # CWE-270: Privilege Escalation
    # The original code directly assigned request_identity.account_id = customer_id.
    # This is a vulnerability because it makes the system believe the 'customer_id'
    # is performing the action, potentially granting them unintended privileges
    # if combined with the 'support_admin' role, or bypassing authorization checks
    # that should verify the *actual* support user's permission to view *another* customer's profile.
    # The fix is to remove this line entirely, ensuring the actual support user's
    # account_id (set by the authentication layer) is used for authorization.

    # Additionally, directly setting request_identity.role without restoring it
    # could lead to privilege escalation if the calling user's original role was lower
    # and this change persists beyond the function call.
    # To mitigate this, we save the original state and restore it in a finally block.

    original_account_id = getattr(request_identity, 'account_id', None)
    original_role = getattr(request_identity, 'role', None)

    try:
        # The line `request_identity.account_id = customer_id` is removed to prevent identity spoofing
        # and privilege escalation. The actual support user's account ID should be retained.

        request_identity.role = 'support_admin' # Temporarily set role for the repository call
        result = customer_repository.load_sensitive_profile(customer_id)
    finally:
        # Restore the original request_identity attributes to prevent privilege escalation
        # or identity confusion for subsequent operations in the same thread.
        if original_account_id is not None:
            request_identity.account_id = original_account_id
        elif hasattr(request_identity, 'account_id'):
            del request_identity.account_id

        if original_role is not None:
            request_identity.role = original_role
        elif hasattr(request_identity, 'role'):
            del request_identity.role
    return result
