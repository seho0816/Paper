class KeyService:
    def Exchange(
        self,
        request,
        context,
    ):
        peer_key = load_x25519_public_key(
            request.public_key
        )
        private_key = generate_x25519_private_key()
        shared_secret = private_key.exchange(
            peer_key
        )

        return {
            "channel_key": derive_channel_key(
                shared_secret
            ),
        }
