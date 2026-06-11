import os

ROTATION_ACTION_TOKEN = os.environ["API_KEY_ROTATION_SECRET_TOKEN"]


def rotate_api_key(
    request_json: dict,
) -> str:
    if request_json.get(
        'action_token'
    ) != ROTATION_ACTION_TOKEN:
        raise PermissionError(
            'invalid action token'
        )
    return api_key_service.rotate(
        request_json['account_id']
    )
