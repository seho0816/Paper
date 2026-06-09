import pickle
from pathlib import Path
import os
from cryptography.fernet import Fernet


def persist_oauth_tokens(tokens: dict) -> None:
    encryption_key = os.environ["OAUTH_ENCRYPTION_KEY"].encode('ascii')
    f = Fernet(encryption_key)

    pickled_tokens = pickle.dumps(tokens)
    encrypted_tokens = f.encrypt(pickled_tokens)

    with (Path.home() / ".oauth_tokens.pkl").open("wb") as output:
        output.write(encrypted_tokens)
