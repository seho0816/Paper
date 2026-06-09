import threading
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, declarative_base

_current_user = threading.local()

def set_current_user_id(user_id: int):
    _current_user.id = user_id

def get_current_user_id() -> int | None:
    return getattr(_current_user, 'id', None)

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)

class MedicalRecord(Base):
    __tablename__ = 'medical_records'
    id = Column(Integer, primary_key=True)
    description = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User")

def load_medical_record(session, record_pk: int):
    current_user_id = get_current_user_id()

    if current_user_id is None:
        raise PermissionError("No authenticated user context found.")

    return (
        session.query(MedicalRecord)
        .filter(MedicalRecord.id == record_pk, MedicalRecord.user_id == current_user_id)
        .one_or_none()
    )
