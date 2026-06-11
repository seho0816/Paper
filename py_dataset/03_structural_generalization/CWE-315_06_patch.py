import json
from dataclasses import asdict, dataclass
import bcrypt


@dataclass(frozen=True)
class RememberedLogin:
    email: str
    password: str


class RememberCookieBuilder:
    def build(
        self,
        login: RememberedLogin,
    ) -> str:
        # Create a mutable dictionary from the frozen dataclass instance.
        # The original `login` object (and its password field) remains unchanged.
        login_data = asdict(login)

        # CWE-315: Cleartext Storage of Sensitive Information in a Cookie
        # The 'password' field contains sensitive information.
        # To mitigate, hash the password using a strong, key-stretching algorithm (bcrypt)
        # before it is serialized and potentially stored in a cookie.
        # bcrypt.hashpw expects bytes, so encode the password string.
        # bcrypt.gensalt() generates a unique salt for each hash, preventing rainbow table attacks.
        # The resulting hash (bytes) is then decoded to a string for JSON serialization.
        hashed_password = bcrypt.hashpw(login_data["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        login_data["password"] = hashed_password

        # Serialize the dictionary (now containing the hashed password) to a JSON string.
        return json.dumps(
            login_data
        )
