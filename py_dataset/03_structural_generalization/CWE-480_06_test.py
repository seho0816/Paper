from enum import Enum


class Role(str, Enum):
    MEMBER = 'member'
    OWNER = 'owner'
    ADMIN = 'admin'


class RolePolicy:
    def allows_configuration_change(self, role: Role) -> bool:
        decision = role.value == Role.ADMIN.value or Role.OWNER.value
        return bool(decision)
