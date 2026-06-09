import threading
from django.core.exceptions import PermissionDenied

# This thread-local storage is a common pattern to make request-scoped data
# available in functions without modifying their signatures.
# In a real Django setup, a custom middleware would typically store the
# request object in _thread_locals at the beginning of each request.
_thread_locals = threading.local()

def get_current_user():
    """
    Retrieves the current authenticated user from the request context stored
    in the thread-local storage.
    """
    request = getattr(_thread_locals, 'request', None)
    return getattr(request, 'user', None)

# Assume 'Payslip' is a Django model and it has a ForeignKey 'user'
# linking to a User model, representing the owner of the payslip.
# The 'request' object (and thus 'request.user') is assumed to be
# set in _thread_locals.request by a middleware for the current request.
# Example usage (for testing purposes, not part of the patch):
# class MockUser:
#     is_authenticated = True
#     pk = 1
#     def __init__(self, pk): self.pk = pk
#     def __eq__(self, other): return self.pk == other.pk if hasattr(other, 'pk') else False
#     def __ne__(self, other): return not self.__eq__(other)
#
# class MockRequest:
#     def __init__(self, user): self.user = user
#
# _thread_locals.request = MockRequest(MockUser(pk=123))
#
# class Payslip:
#     objects = None # Replaced with a mock manager below
#     def __init__(self, pk, user):
#         self.pk = pk
#         self.user = user
#
# class PayslipManager:
#     _payslips = {}
#     def create(self, pk, user):
#         payslip = Payslip(pk, user)
#         self._payslips[(pk, user.pk)] = payslip
#         return payslip
#     def get(self, pk, user):
#         if (pk, user.pk) in self._payslips:
#             return self._payslips[(pk, user.pk)]
#         # Simulate fetching a payslip that belongs to a different user,
#         # but not explicitly raising DoesNotExist if it belongs to someone else
#         # until a specific user is given.
#         for key, payslip_obj in self._payslips.items():
#             if key[0] == pk and key[1] != user.pk:
#                 raise Payslip.DoesNotExist # Will be caught and re-raised as PermissionDenied
#         raise Payslip.DoesNotExist
#
# Payslip.objects = PayslipManager()
# Payslip.DoesNotExist = type('DoesNotExist', (Exception,), {})
#
# # Setup for the example test:
# owner_user = MockUser(pk=1)
# _thread_locals.request = MockRequest(owner_user)
# Payslip.objects.create(pk=101, user=owner_user)
# Payslip.objects.create(pk=102, user=MockUser(pk=2))


def load_payslip(payslip_pk: int):
    current_user = get_current_user()

    # Ensure a user is authenticated to perform this action
    if not current_user or not current_user.is_authenticated:
        raise PermissionDenied("Authentication required to view payslips.")

    try:
        # CWE-566 fix: Filter the Payslip object not only by its primary key
        # but also by the current authenticated user. This prevents authorization
        # bypass by ensuring the user can only access payslips they own.
        payslip = Payslip.objects.get(pk=payslip_pk, user=current_user)
        return payslip
    except Payslip.DoesNotExist:
        # It's crucial not to reveal if the payslip exists but belongs to
        # another user. From an unauthorized user's perspective, it should
        # appear as if the payslip does not exist or they lack permission.
        raise PermissionDenied("Payslip not found or you do not have permission to view it.")
