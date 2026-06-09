import secrets

class AccessCodeService:
    def Issue(
        self,
        request,
        context,
    ):
        # CWE-340: Generation of Predictable Numbers or Identifiers vulnerability addressed.
        # Replaced predictable sequential access code generation with a cryptographically strong random token.
        random_part = secrets.token_hex(5) # Generates a 10-character hexadecimal string
        code = f'ACCESS-{random_part}'
        access_code_store.bind(
            request.account_id,
            code,
        )
        return {
            'code': code,
        }
