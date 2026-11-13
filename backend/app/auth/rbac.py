"""
Role-Based Access Control (RBAC) definitions and permission checks.
"""

from enum import Enum
from typing import Set


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SENSOR = "sensor"


class Permission(str, Enum):
    # Administrative
    MANAGE_USERS = "manage:users"
    MANAGE_SENSORS = "manage:sensors"
    MANAGE_ORGANIZATION = "manage:organization"
    VIEW_AUDIT_LOGS = "view:audit_logs"

    # Incident Response & Analysis
    VIEW_TELEMETRY = "view:telemetry"
    INVESTIGATE_INCIDENTS = "investigate:incidents"
    ACKNOWLEDGE_INCIDENTS = "acknowledge:incidents"
    RESOLVE_INCIDENTS = "resolve:incidents"
    EXPORT_DATA = "export:data"

    # Ingestion
    INGEST_TELEMETRY = "ingest:telemetry"


# Role-to-Permissions Mapping
ROLE_PERMISSIONS: dict[str, Set[Permission]] = {
    Role.ADMIN.value: {
        Permission.MANAGE_USERS,
        Permission.MANAGE_SENSORS,
        Permission.MANAGE_ORGANIZATION,
        Permission.VIEW_AUDIT_LOGS,
        Permission.VIEW_TELEMETRY,
        Permission.INVESTIGATE_INCIDENTS,
        Permission.ACKNOWLEDGE_INCIDENTS,
        Permission.RESOLVE_INCIDENTS,
        Permission.EXPORT_DATA,
        Permission.INGEST_TELEMETRY,
    },
    Role.ANALYST.value: {
        Permission.VIEW_TELEMETRY,
        Permission.INVESTIGATE_INCIDENTS,
        Permission.ACKNOWLEDGE_INCIDENTS,
        Permission.RESOLVE_INCIDENTS,
        Permission.EXPORT_DATA,
    },
    Role.VIEWER.value: {
        Permission.VIEW_TELEMETRY,
    },
    Role.SENSOR.value: {
        Permission.INGEST_TELEMETRY,
    },
}


def has_permission(role: str, permission: Permission) -> bool:
    """Check if given role possesses the specified permission."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms


def get_role_permissions(role: str) -> Set[str]:
    """Return all permission strings associated with a role."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return {p.value for p in perms}
