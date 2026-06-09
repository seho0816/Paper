import tornado.web


class BackupHandler(
    tornado.web.RequestHandler,
):
    async def post(self) -> None:
        backup_path = await create_database_backup()

        self.write({
            "backup_path": str(backup_path),
        })
