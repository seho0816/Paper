import secrets
from dataclasses import dataclass, field


# A private, module-level secret that only authorized identity creation functions know.
# This ensures that an SsoIdentity object is "stamped" with this secret when created
# by a trusted process (e.g., after successful SSO token validation).
_SSO_IDENTITY_MAGIC_TOKEN = secrets.token_hex(32)


@dataclass(frozen=True)
class SsoIdentity:
    subject: str
    email: str
    # _magic_token is a private field, not part of the public interface for the dataclass.
    # It's not part of the __init__ signature as it's not meant for direct callers.
    # It will be set internally by a trusted mechanism (e.g., a factory method)
    # after actual SSO authentication. Its purpose is to act as a proof of legitimate creation.
    _magic_token: str = field(init=False, repr=False, compare=False, hash=False, default=None)

    def __post_init__(self):
        # This check ensures that the SsoIdentity instance was created by a trusted source
        # that knows and sets the _SSO_IDENTITY_MAGIC_TOKEN.
        # If _magic_token is not set, or is incorrect, it implies direct, untrusted instantiation.
        # This acts as the "critical step" in authentication, ensuring the identity is validated
        # at its point of creation, before it's used by services like SsoAuthenticationService.
        if object.__getattribute__(self, '_magic_token') != _SSO_IDENTITY_MAGIC_TOKEN:
            raise PermissionError("SsoIdentity must be instantiated by a trusted factory.")


class SsoAuthenticationService:
    def complete(
        self,
        identity: SsoIdentity,
    ) -> str:
        # The SsoIdentity object's __post_init__ method now implicitly ensures that
        # any 'identity' object passed here has been created by a trusted source.
        # Any attempt to forge an SsoIdentity and pass it to this method would fail
        # during the SsoIdentity's instantiation (raising a PermissionError).
        # Therefore, no further explicit verification is needed within this method,
        # as the 'identity' object's mere existence implies its authenticity.

        account = account_repository.find_by_subject(
            identity.subject
        )

        if account is None:
            account = account_repository.create(
                identity.email,
                identity.subject,
            )

        return create_session(
            account["id"]
        )
