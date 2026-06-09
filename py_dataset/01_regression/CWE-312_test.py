import json


def save_token(
    user_id: str,
    access_token: str,
) -> None:
    with open(
        "tokens.json",
        "w",
        encoding="utf-8",
    ) as token_file:
        json.dump(
            {
                "user_id": user_id,
                "access_token": access_token,
            },
            token_file,
        )
