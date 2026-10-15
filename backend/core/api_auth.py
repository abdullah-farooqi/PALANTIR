import hmac
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.config import settings

_bearer = HTTPBearer(auto_error=False)


async def get_api_role(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> str:
    configured_tokens = {
        "read": settings.PALANTIR_API_READ_TOKEN,
        "admin": settings.PALANTIR_API_ADMIN_TOKEN,
        "enroll": settings.PALANTIR_API_ENROLL_TOKEN,
    }
    active_tokens = [(role, token) for role, token in configured_tokens.items() if token]

    if not active_tokens:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )
    if len({token for _, token in active_tokens}) != len(active_tokens):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication tokens must be distinct",
        )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    for role, token in active_tokens:
        if hmac.compare_digest(
            credentials.credentials.encode("utf-8"), token.encode("utf-8")
        ):
            return role

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid bearer token",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_read(role: str = Depends(get_api_role)) -> None:
    if role not in {"read", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Read access required",
        )


async def require_admin(role: str = Depends(get_api_role)) -> None:
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Node-management access required",
        )


async def require_node_enrollment(role: str = Depends(get_api_role)) -> str:
    if role not in {"admin", "enroll"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Node-enrollment access required",
        )
    return role
