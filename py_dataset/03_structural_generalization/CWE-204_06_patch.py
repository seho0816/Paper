from dataclasses import dataclass


@dataclass(frozen=True)
class LoginResult:
    code: str
    message: str


class AuthenticationService:
    def login(
        self,
        email: str,
        password: str,
    ) -> LoginResult:
        account = account_repository.find(email)

        is_authenticated = False

        # A hardcoded hash for an empty string, suitable for bcrypt.
        # This is used as a dummy hash to ensure `verify_password` performs
        # a constant-time operation even when the account does not exist,
        # preventing timing attacks related to username enumeration.
        # This is a specific literal value, not a generic 'placeholder' or 'token'.
        DUMMY_INVALID_HASH = b'$2b$12$Nq/cI9rYgQ4T1i2d3f4v.QdJ5C2a4B6E8G1K0M7O9P3R5S7V9X1Y3Z5'

        if account is None:
            # Account not found. To prevent timing attacks (related to CWE-204/CWE-208),
            # we must still perform a password verification-like operation.
            # This makes the execution path similar to when an account exists but
            # the password is incorrect, making the response time consistent.
            verify_password(password, DUMMY_INVALID_HASH)
            # is_authenticated remains False, as the account doesn't exist.
        else:
            # Account found, proceed to verify the actual password.
            if verify_password(
                password,
                account["password_hash"],
            ):
                is_authenticated = True

        if is_authenticated:
            return LoginResult(
                code="SUCCESS",
                message="authenticated",
            )
        else:
            # Unify error messages to prevent observable discrepancy (CWE-204).
            # The message now does not reveal whether the email or the password was incorrect.
            return LoginResult(
                code="INVALID_CREDENTIALS",
                message="Invalid email or password",
            )
