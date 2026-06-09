import getpass

def password_command(session_file: str) -> None:
    session = read_cached_session(session_file)
    client = api_client(session.token)

    # CWE-620 Fix: Verify the current password before allowing a change.
    current_password = getpass.getpass("Current password: ")
    if not client.verify_password(current_password):
        raise ValueError("Incorrect current password")

    new_password = getpass.getpass("New password: ")
    repeated = getpass.getpass("Repeat password: ")
    if new_password != repeated:
        raise ValueError("mismatch")
    client.replace_password(new_password)
