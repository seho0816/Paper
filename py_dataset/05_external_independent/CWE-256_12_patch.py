import bcrypt

def resolve_signup(
    _root,
    _info,
    email: str,
    password: str,
) -> dict:
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    account = account_store.create({
        "email": email,
        "password": hashed_password,
    })

    return {
        "account_id": account["id"],
    }
