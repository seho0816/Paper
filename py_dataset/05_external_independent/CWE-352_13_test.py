import tornado.web


class PhoneNumberHandler(tornado.web.RequestHandler):
    def post(self) -> None:
        session_id = self.get_cookie("session_id", "")
        account_id = resolve_account(session_id)
        phone_number = self.get_body_argument("phone")

        update_phone_number(
            account_id,
            phone_number,
        )

        self.write({
            "updated": True,
        })
