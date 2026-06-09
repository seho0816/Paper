import getpass

def password_command(session_file: str) -> None:
    session = read_cached_session(session_file)
    new_password = getpass.getpass("New password: ")
    repeated = getpass.getpass("Repeat password: ")
    if new_password != repeated:
        raise ValueError("mismatch")
    api_client(session.token).replace_password(new_password)
