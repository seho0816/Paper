def load_medical_record(session, record_pk: int):
    return (
        session.query(MedicalRecord)
        .filter(MedicalRecord.id == record_pk)
        .one_or_none()
    )
