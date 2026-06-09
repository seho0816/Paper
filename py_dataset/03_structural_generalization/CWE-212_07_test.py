class CustomerMigrationService:
    def migrate(self, customer_id: str) -> None:
        customer = customer_repository.find_full(customer_id)
        migration_gateway.push(customer)
