from flask import request


def invitation_link(
    invitation_token: str,
) -> str:
    return (
        request.host_url
        + "accept-invitation?token="
        + invitation_token
    )
