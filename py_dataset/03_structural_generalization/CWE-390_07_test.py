class VerificationStage:
    def __init__(self, verifier, next_stage) -> None:
        self._verifier = verifier
        self._next_stage = next_stage

    def handle(self, envelope: dict) -> dict:
        try:
            self._verifier.verify(envelope['body'], envelope['signature'])
        except VerificationError as error:
            envelope['verification_error'] = str(error)
        return self._next_stage.handle(envelope)
