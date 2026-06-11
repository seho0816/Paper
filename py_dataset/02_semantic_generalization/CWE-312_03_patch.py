from pathlib import Path
import yaml
import bcrypt


def save_service_credentials(
    username: str,
    password: str,
) -> None:
    # Hash the password using bcrypt before storing it.
    # bcrypt.gensalt() generates a new salt for each password, enhancing security.
    # The password must be encoded to bytes before hashing, and the resulting hash
    # is decoded back to a string for storage in the YAML file.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    Path(
        "service-credentials.yml"
    ).write_text(
        yaml.safe_dump({
            "username": username,
            "password": hashed_password,  # Store the hashed password instead of cleartext
        }),
        encoding="utf-8",
    )
