from .models import Domain, Host, HostSet


def _resolve_scope_object(scope_type, scope_id):
    if scope_type == "domain":
        return Domain.objects.filter(pk=scope_id).first()
    if scope_type == "host_set":
        return HostSet.objects.filter(pk=scope_id).first()
    if scope_type == "host":
        return Host.objects.filter(pk=scope_id).first()
    return None