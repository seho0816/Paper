def migrate_customer(customer: dict) -> None:
    migration_client.send({
        "customer": customer,
        "source": "legacy",
    })
