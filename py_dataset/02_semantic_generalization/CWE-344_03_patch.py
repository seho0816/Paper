from typing import Callable

# This class acts as a proxy to retrieve the CSRF token dynamically at the point of comparison.
# It ensures that `APPLICATION_CSRF_VALUE` always represents the *current* expected token,
# even though it's assigned once globally.
class DynamicCSRFToken:
    def __init__(self, token_retriever: Callable[[], str]):
        if not callable(token_retriever):
            raise TypeError("token_retriever must be a callable that returns the current CSRF token.")
        self._token_retriever = token_retriever

    def __eq__(self, other) -> bool:
        # Retrieve the current, dynamic token when equality is checked
        return self._token_retriever() == other

    def __ne__(self, other) -> bool:
        # Retrieve the current, dynamic token when inequality is checked
        return self._token_retriever() != other

    def __str__(self) -> str:
        # Provide a string representation (e.g., for logging or debugging)
        return self._token_retriever()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} (current_value_preview='{self._token_retriever()[:8]}...')>"

# To fix CWE-344, APPLICATION_CSRF_VALUE must be dynamic.
# We assume settings.CSRF_VALUE now provides a *callable* function
# that retrieves the current, session-specific, or request-specific CSRF token.
# The `DynamicCSRFToken` class wraps this callable.
APPLICATION_CSRF_VALUE = DynamicCSRFToken(settings.CSRF_VALUE)


def submit_payment_method(
    form: dict,
) -> None:
    if form.get(
        'csrf'
    ) != APPLICATION_CSRF_VALUE:
        raise PermissionError(
            'CSRF validation failed'
        )
    payment_method_repository.save(
        form['payment_method']
    )
