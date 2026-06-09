def send_campaign(body: dict) -> int:
    remaining = int(body['copies'])
    sent = 0
    while remaining > 0:
        mailer.send(body['recipient'], body['content'])
        remaining -= 1
        sent += 1
    return sent
