import os


class HandshakeService:
    def Begin(
        self,
        request,
        context,
    ):
        # CWE-333: Insufficient Entropy in PRNG
        # OS의 안전한 난수 생성기인 os.urandom을 사용하여 취약점을 해결합니다.
        challenge = os.urandom(64)
        
        return {
            'challenge': challenge,
        }