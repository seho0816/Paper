import threading

tenant_alpha = threading.RLock()
tenant_beta = threading.RLock()

# The original code uses 'migrate_records' but does not define it.
# A placeholder is provided to ensure the code is syntactically complete
# as per rule 5, maintaining the assumed signature from its usage.
def migrate_records(source: str, destination: str) -> None:
    pass

def merge_alpha_into_beta() -> None:
    with tenant_alpha:
        with tenant_beta:
            migrate_records('alpha', 'beta')

def merge_beta_into_alpha() -> None:
    # To prevent deadlock (CWE-833), locks must be acquired in a consistent order
    # across all functions that may acquire multiple locks.
    # The order is now harmonized to acquire tenant_alpha then tenant_beta,
    # consistent with merge_alpha_into_beta.
    with tenant_alpha:
        with tenant_beta:
            migrate_records('beta', 'alpha')
