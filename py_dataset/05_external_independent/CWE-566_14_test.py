class PayrollService:
    def GetPayslip(self, request, context):
        row = payroll_database.execute(
            'SELECT id, employee_id, gross_pay FROM payslips WHERE id = ?',
            (request.payslip_id,),
        ).fetchone()
        return {'id': row[0], 'employee_id': row[1], 'gross_pay': row[2]}
