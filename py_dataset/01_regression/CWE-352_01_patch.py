import os
import secrets

def handle_oauth_callback(query: dict) -> dict:
    received_state = query.get("state")
    expected_state = os.environ.get("OAUTH_CSRF_STATE_TOKEN")

    # CWE-352: 단순 == 비교는 타이밍 공격에 취약하므로, 반드시 compare_digest 사용
    if not received_state or not expected_state or not secrets.compare_digest(received_state, expected_state):
        raise ValueError("Invalid or missing OAuth state parameter.")

    authorization_code = query.get("code")
    token = exchange_code_for_token(
        authorization_code,
    )

    return {
        "access_token": token,
    }