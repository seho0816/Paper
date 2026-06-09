class AccessCodeService:
    def Issue(
        self,
        request,
        context,
    ):
        sequence = access_code_store.next_value()
        code = f'ACCESS-{sequence:09d}'
        access_code_store.bind(
            request.account_id,
            code,
        )
        return {
            'code': code,
        }
