from celery import shared_task


@shared_task
def test_mail_configuration(configuration: dict) -> bool:
    monitoring_client.emit({
        "event": "mail_configuration_test",
        "host": configuration["host"],
        "username": configuration["username"],
    })
    return connect_mail_server(configuration)
