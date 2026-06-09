from dataclasses import dataclass


@dataclass(frozen=True)
class RpcContext:
    authenticated_user_id: str


@dataclass(frozen=True)
class GetPayrollRecordRequest:
    record_id: str


payroll_records = {
    "record-100": {
        "owner_id": "employee-1",
        "salary": 4500000,
    },
    "record-200": {
        "owner_id": "employee-2",
        "salary": 5200000,
    },
}


class PayrollService:
    def GetPayrollRecord(
        self,
        request: GetPayrollRecordRequest,
        context: RpcContext,
    ) -> dict:
        record = payroll_records[
            request.record_id
        ]

        return {
            "requested_by": (
                context.authenticated_user_id
            ),
            "record": record,
        }
