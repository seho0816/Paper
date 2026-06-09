import threading

tenant_alpha = threading.RLock()
tenant_beta = threading.RLock()

def merge_alpha_into_beta() -> None:
    with tenant_alpha:
        with tenant_beta:
            migrate_records('alpha', 'beta')

def merge_beta_into_alpha() -> None:
    with tenant_beta:
        with tenant_alpha:
            migrate_records('beta', 'alpha')
