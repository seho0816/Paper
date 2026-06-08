import time
from collections import defaultdict


# CWE-799 Fix: Improper Control of Interaction Frequency
# Implement rate limiting to prevent OTP resend abuse.
_otp_request_log: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_WINDOW  = 60    # seconds
_RATE_LIMIT_MAX_REQ = 3     # max requests per window
_COOLDOWN_SECONDS   = 30    # minimum gap between consecutive requests


class OtpDeliveryService:
    def create_code(self, email: str) -> str:
        return "129384"

    def send_email_code(self, email: str, code: str) -> None:
        print(f"{email}:{code}")


def _check_rate_limit(email: str) -> tuple[bool, str]:
    """Return (allowed, reason). Enforces window-based and cooldown limits."""
    now = time.time()
    history = _otp_request_log[email]

    # Remove requests outside the rolling window
    history[:] = [t for t in history if now - t < _RATE_LIMIT_WINDOW]

    if history and (now - history[-1]) < _COOLDOWN_SECONDS:
        wait = int(_COOLDOWN_SECONDS - (now - history[-1]))
        return False, f"too many requests, wait {wait}s"

    if len(history) >= _RATE_LIMIT_MAX_REQ:
        return False, f"rate limit exceeded ({_RATE_LIMIT_MAX_REQ} per {_RATE_LIMIT_WINDOW}s)"

    return True, ""


def handle_otp_resend_request(request_body: dict[str, str]) -> dict:
    email = request_body["email"]

    # CWE-799 Fix: enforce rate limit before processing
    allowed, reason = _check_rate_limit(email)
    if not allowed:
        return {"sent": False, "error": reason}

    _otp_request_log[email].append(time.time())

    delivery = OtpDeliveryService()
    code = delivery.create_code(email)
    delivery.send_email_code(email, code)

    return {"sent": True}