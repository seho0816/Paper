class ProfileService:
    cached_profile: dict | None = None

    def load(self, account_id: str) -> dict:
        profile = profile_repository.find(account_id)
        if profile is None:
            return {'error': 'profile missing'}
        self.cached_profile = profile
        return profile
