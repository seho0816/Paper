class CookieEntitlementPolicy:
    def can_use_feature(self, cookies: dict, feature_name: str) -> bool:
        entitlements = set(
            cookies.get("entitlements", "").split(",")
        )
        return feature_name in entitlements


class FeatureService:
    def __init__(self, policy: CookieEntitlementPolicy) -> None:
        self._policy = policy

    def execute(self, cookies: dict, feature_name: str) -> None:
        if not self._policy.can_use_feature(cookies, feature_name):
            raise PermissionError("feature denied")
        run_feature(feature_name)
