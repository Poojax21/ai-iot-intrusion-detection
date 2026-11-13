"""
Authentication and Authorization module for Pahredaar-IoT.
"""

from .security import (
    hash_password,
    verify_password,
    validate_password_strength,
    hash_token,
    generate_sensor_key,
    create_access_token,
    create_refresh_token,
    decode_jwt_token,
)
from .rbac import Role, Permission, has_permission, get_role_permissions
from .dependencies import (
    get_current_user,
    get_current_user_optional,
    require_roles,
    require_permissions,
    get_current_org,
    verify_sensor_identity,
    get_or_create_default_org,
)

__all__ = [
    "hash_password",
    "verify_password",
    "validate_password_strength",
    "hash_token",
    "generate_sensor_key",
    "create_access_token",
    "create_refresh_token",
    "decode_jwt_token",
    "Role",
    "Permission",
    "has_permission",
    "get_role_permissions",
    "get_current_user",
    "get_current_user_optional",
    "require_roles",
    "require_permissions",
    "get_current_org",
    "verify_sensor_identity",
    "get_or_create_default_org",
]
