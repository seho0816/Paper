import random
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class OAuthAuthorization:
    provider: str
    state: str
    featured_scopes: list[str]


def select_featured_scopes(
    available_scopes: list[str],
    count: int = 2,
) -> list[str]:
    sample_size = min(count, len(available_scopes))
    return random.sample(available_scopes, sample_size)


def create_oauth_authorization(
    provider: str,
    available_scopes: list[str],
) -> OAuthAuthorization:
    return OAuthAuthorization(
        provider=provider,
        state=secrets.token_urlsafe(32),
        featured_scopes=select_featured_scopes(
            available_scopes,
        ),
    )
