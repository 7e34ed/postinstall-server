from enum import Enum


class Role(str, Enum):
    SUPERVISOR = "supervisor"
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    VIEWER = "viewer"
    SERVICE = "service"


class ScopeType(str, Enum):
    GLOBAL = "global"
    DOMAIN = "domain"
    HOST_SET = "host_set"
    HOST = "host"


# Числовой «вес» — для сравнений «не ниже уровня».
ROLE_WEIGHT = {
    Role.VIEWER: 1,
    Role.AUDITOR: 2,
    Role.OPERATOR: 3,
    Role.ADMIN: 4,
    Role.SUPERVISOR: 5,
    Role.SERVICE: 0,
}


ROLE_LABELS = {
    Role.SUPERVISOR: "Супервизор",
    Role.ADMIN: "Администратор",
    Role.OPERATOR: "Оператор",
    Role.AUDITOR: "Аудитор",
    Role.VIEWER: "Наблюдатель",
    Role.SERVICE: "Сервисный аккаунт",
}


SCOPE_LABELS = {
    ScopeType.GLOBAL: "Глобально",
    ScopeType.DOMAIN: "Домен",
    ScopeType.HOST_SET: "Набор хостов",
    ScopeType.HOST: "Хост",
}


# Роли, требующие двухстороннего подтверждения при инвайте.
DUAL_APPROVAL_ROLES = {Role.SUPERVISOR, Role.ADMIN}

# Роли, которые SUPERVISOR может выдавать через инвайт.
SUPERVISOR_CAN_INVITE = {Role.ADMIN}
ADMIN_CAN_INVITE = {Role.OPERATOR, Role.AUDITOR, Role.VIEWER}