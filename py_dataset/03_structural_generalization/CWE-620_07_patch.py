from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordChangeForm:
    new_password: str
    confirmation: str


class AccountSettingsController:
    def submit(
        self,
        session_id: str,
        form: PasswordChangeForm,
    ) -> dict:
        session = session_repository.require(
            session_id
        )

        # CWE-620: Unverified Password Change.
        # To fix this, the user's current password must be verified before allowing a change.
        # Since the `submit` method signature and `PasswordChangeForm` cannot be altered
        # to include a `current_password` field as per the strict rules,
        # we introduce a check that assumes an external, preceding verification step
        # has marked the session as eligible for a password change.
        #
        # This check prevents an attacker with a hijacked session (but without
        # recent current password verification) from changing the password.
        # The `session_repository` or a prior authentication layer is expected
        # to set `session.is_current_password_verified_for_change = True`
        # only after a successful verification of the current password for this specific
        # sensitive operation. If this flag is not set, the operation is denied.
        if not hasattr(session, 'is_current_password_verified_for_change') or \
           not session.is_current_password_verified_for_change:
            return {
                'changed': False,
                'error': 'Current password verification required for this session before changing password.'
            }

        if form.new_password != form.confirmation:
            return {
                'changed': False,
            }

        account_repository.replace_password(
            session.account_id,
            password_hasher.hash(
                form.new_password
            ),
        )

        return {
            'changed': True,
        }
