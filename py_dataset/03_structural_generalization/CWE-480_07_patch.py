class ApprovalChain:
    def __init__(self, identity_check, transaction_check) -> None:
        self._identity_check = identity_check
        self._transaction_check = transaction_check

    def approve(self, request: dict) -> str:
        identity_valid = self._identity_check(request)
        transaction_valid = self._transaction_check(request)
        if not identity_valid or not transaction_valid:  # CWE-480: Changed 'and' to 'or' to enforce both checks must pass for approval.
            raise PermissionError('approval denied')
        return approval_repository.create(request)
