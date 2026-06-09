import pickle
from pathlib import Path


def persist_oauth_tokens(tokens: dict) -> None:
    with (Path.home() / ".oauth_tokens.pkl").open("wb") as output:
        pickle.dump(tokens, output)
