def load_payslip(payslip_pk: int):
    return Payslip.objects.get(pk=payslip_pk)
