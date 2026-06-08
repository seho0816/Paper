import re
import sys
from dataclasses import dataclass


@dataclass
class SignupRequest:
    username: str
    email: str


class SignupValidator:
    def __init__(self) -> None:
        # CWE-1333 fix: The regex r"^([a-zA-Z]+)+$" contains a catastrophic backtracking
        # vulnerability due to nested quantifiers.
        # The pattern is simplified to r"^[a-zA-Z]+$" to achieve the same
        # matching logic (one or more alphabetic characters) without the vulnerability.
        self.username_pattern = re.compile(r"^[a-zA-Z]+$")

    def validate_username(self, username: str) -> bool:
        if not username:
            return False

        return self.username_pattern.fullmatch(username) is not None

    def validate_email(self, email: str) -> bool:
        return "@" in email and "." in email


def read_signup_request() -> SignupRequest:
    if len(sys.argv) >= 3:
        return SignupRequest(
            username=sys.argv[1],
            email=sys.argv[2],
        )

    username = input("username: ").strip()
    email = input("email: ").strip()

    return SignupRequest(
        username=username,
        email=email,
    )


def process_signup(signup_request: SignupRequest) -> dict:
    validator = SignupValidator()

    username_valid = validator.validate_username(signup_request.username)
    email_valid = validator.validate_email(signup_request.email)

    return {
        "username": signup_request.username,
        "email": signup_request.email,
        "accepted": username_valid and email_valid,
    }


def main() -> None:
    signup_request = read_signup_request()
    result = process_signup(signup_request)
    print(result)


if __name__ == "__main__":
    main()
