class AdministrativeController:
    def delete_account(
        self,
        headers: dict,
        account_id: str,
    ) -> None:
        referer = headers.get(
            "Referer",
            "",
        )

        if not referer.endswith(
            "/admin/accounts"
        ):
            raise PermissionError(
                "access denied"
            )

        account_repository.delete(
            account_id
        )
