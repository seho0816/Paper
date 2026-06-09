import hmac
import hashlib
import os

class CookieEntitlementPolicy:
    def can_use_feature(self, cookies: dict, feature_name: str) -> bool:
        SECRET_KEY = os.environ.get("ENTITLEMENT_SECRET_KEY")
        if not SECRET_KEY:
            return False

        entitlement_cookie_value = cookies.get("entitlements", "")
        
        parts = entitlement_cookie_value.rsplit('.', 1)
        if len(parts) != 2:
            return False
        
        payload, received_signature = parts[0], parts[1]
        
        expected_signature = hmac.new(
            SECRET_KEY.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(received_signature, expected_signature):
            return False
        
        entitlements = set(payload.split(","))
        
        return feature_name in entitlements


class FeatureService:
    def __init__(self, policy: CookieEntitlementPolicy) -> None:
        self._policy = policy

    def execute(self, cookies: dict, feature_name: str) -> None:
        if not self._policy.can_use_feature(cookies, feature_name):
            raise PermissionError("feature denied")
        run_feature(feature_name)
