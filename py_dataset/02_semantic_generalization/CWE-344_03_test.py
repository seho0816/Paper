APPLICATION_CSRF_VALUE = settings.CSRF_VALUE


def submit_payment_method(
    form: dict,
) -> None:
    if form.get(
        'csrf'
    ) != APPLICATION_CSRF_VALUE:
        raise PermissionError(
            'CSRF validation failed'
        )
    payment_method_repository.save(
        form['payment_method']
    )
