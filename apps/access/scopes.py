"""
Резолвер scope объекта.

Правило: у каждого объекта есть «место в иерархии»:
  Global → Domain → HostSet → Host

Утилита определяет наиболее специфичный scope объекта, чтобы
проверка прав работала однообразно.
"""
from __future__ import annotations

from dataclasses import dataclass

from .roles import ScopeType


@dataclass(frozen=True)
class ObjectScope:
    scope_type: str
    scope_id: int
    domain_id: int | None = None
    host_set_id: int | None = None
    host_id: int | None = None

    @property
    def is_global(self) -> bool:
        return self.scope_type == ScopeType.GLOBAL.value


GLOBAL = ObjectScope(scope_type=ScopeType.GLOBAL.value, scope_id=0)


def scope_for_object(obj) -> ObjectScope:
    """Определить scope объекта.

    Поддерживаются:
      * Host → HOST
      * HostSet → HOST_SET
      * Domain → DOMAIN
      * Credential → по своим FK (host/host_set/domain)
      * SecretRef → по своим FK
      * Deployment → по host
      * ConfigProfile, Repository, Certificate, Package → GLOBAL
        (пока; в будущем добавим domain FK)
      * None → GLOBAL
    """
    if obj is None:
        return GLOBAL

    cls_name = type(obj).__name__

    # Host
    if cls_name == "Host":
        return ObjectScope(
            scope_type=ScopeType.HOST.value,
            scope_id=obj.pk,
            domain_id=obj.domain_id,
            host_set_id=obj.host_set_id,
            host_id=obj.pk,
        )

    # HostSet
    if cls_name == "HostSet":
        return ObjectScope(
            scope_type=ScopeType.HOST_SET.value,
            scope_id=obj.pk,
            domain_id=obj.domain_id,
            host_set_id=obj.pk,
        )

    # Domain
    if cls_name == "Domain":
        return ObjectScope(
            scope_type=ScopeType.DOMAIN.value,
            scope_id=obj.pk,
            domain_id=obj.pk,
        )

    # Credential
    if cls_name == "Credential":
        if obj.host_id:
            return ObjectScope(
                scope_type=ScopeType.HOST.value,
                scope_id=obj.host_id,
                domain_id=obj.domain_id or obj.host.domain_id,
                host_set_id=obj.host_set_id or obj.host.host_set_id,
                host_id=obj.host_id,
            )
        if obj.host_set_id:
            return ObjectScope(
                scope_type=ScopeType.HOST_SET.value,
                scope_id=obj.host_set_id,
                domain_id=obj.domain_id or obj.host_set.domain_id,
                host_set_id=obj.host_set_id,
            )
        if obj.domain_id:
            return ObjectScope(
                scope_type=ScopeType.DOMAIN.value,
                scope_id=obj.domain_id,
                domain_id=obj.domain_id,
            )
        return GLOBAL

    # SecretRef
    if cls_name == "SecretRef":
        if obj.host_id:
            return ObjectScope(
                scope_type=ScopeType.HOST.value,
                scope_id=obj.host_id,
                domain_id=obj.domain_id,
                host_set_id=obj.host_set_id,
                host_id=obj.host_id,
            )
        if obj.host_set_id:
            return ObjectScope(
                scope_type=ScopeType.HOST_SET.value,
                scope_id=obj.host_set_id,
                domain_id=obj.domain_id,
                host_set_id=obj.host_set_id,
            )
        if obj.domain_id:
            return ObjectScope(
                scope_type=ScopeType.DOMAIN.value,
                scope_id=obj.domain_id,
                domain_id=obj.domain_id,
            )
        return GLOBAL

    # Deployment
    if cls_name == "Deployment":
        return scope_for_object(obj.host)

    # BulkDeployment
    if cls_name == "BulkDeployment":
        first = obj.deployments.first()
        if first is not None:
            return scope_for_object(first.host)
        return GLOBAL

    # Invitation
    if cls_name == "Invitation":
        return ObjectScope(
            scope_type=obj.scope_type,
            scope_id=obj.scope_id,
        )

    # ConfigProfile, Repository, Certificate, Package, RoleAssignment
    return GLOBAL