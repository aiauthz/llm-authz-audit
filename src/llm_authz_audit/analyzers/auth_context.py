"""Cross-file auth flow tracking — reduces false positives for EP001/EP003."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llm_authz_audit.core.context import ScanContext

_FASTAPI_DEPENDS_PATTERN = re.compile(r"Depends\s*\(", re.IGNORECASE)
_OAUTH2_BEARER_PATTERN = re.compile(r"OAuth2PasswordBearer|OAuth2AuthorizationCodeBearer", re.IGNORECASE)
_FLASK_LOGIN_PATTERN = re.compile(r"login_required|@login_manager", re.IGNORECASE)
_BEFORE_REQUEST_PATTERN = re.compile(r"@app\.before_request|before_request", re.IGNORECASE)
_EXPRESS_PASSPORT_PATTERN = re.compile(r"passport\.authenticate|passport\.initialize", re.IGNORECASE)
_EXPRESS_JWT_PATTERN = re.compile(r"jwt\.verify|jsonwebtoken|express-jwt", re.IGNORECASE)


@dataclass
class AuthContext:
    has_fastapi_depends: bool = False
    has_oauth2_bearer: bool = False
    has_flask_login_required: bool = False
    has_before_request_handler: bool = False
    has_express_passport: bool = False
    has_express_jwt: bool = False
    auth_middleware_files: list[str] = field(default_factory=list)

    @property
    def has_project_auth(self) -> bool:
        return any([
            self.has_fastapi_depends,
            self.has_oauth2_bearer,
            self.has_flask_login_required,
            self.has_before_request_handler,
            self.has_express_passport,
            self.has_express_jwt,
        ])

    @property
    def summary(self) -> str:
        parts = []
        if self.has_fastapi_depends:
            parts.append("FastAPI Depends()")
        if self.has_oauth2_bearer:
            parts.append("OAuth2 Bearer")
        if self.has_flask_login_required:
            parts.append("Flask login_required")
        if self.has_before_request_handler:
            parts.append("before_request handler")
        if self.has_express_passport:
            parts.append("Express Passport")
        if self.has_express_jwt:
            parts.append("Express JWT")
        if self.auth_middleware_files:
            parts.append(f"files: {', '.join(self.auth_middleware_files)}")
        return "; ".join(parts) if parts else "none"


def build_auth_context(context: ScanContext) -> AuthContext:
    """Scan all project files for auth definitions."""
    auth = AuthContext()

    for file_entry in context.files:
        content = file_entry.content
        if not content:
            continue

        if _FASTAPI_DEPENDS_PATTERN.search(content):
            auth.has_fastapi_depends = True
            if file_entry.relative_path not in auth.auth_middleware_files:
                auth.auth_middleware_files.append(file_entry.relative_path)

        if _OAUTH2_BEARER_PATTERN.search(content):
            auth.has_oauth2_bearer = True
            if file_entry.relative_path not in auth.auth_middleware_files:
                auth.auth_middleware_files.append(file_entry.relative_path)

        if _FLASK_LOGIN_PATTERN.search(content):
            auth.has_flask_login_required = True
            if file_entry.relative_path not in auth.auth_middleware_files:
                auth.auth_middleware_files.append(file_entry.relative_path)

        if _BEFORE_REQUEST_PATTERN.search(content):
            auth.has_before_request_handler = True
            if file_entry.relative_path not in auth.auth_middleware_files:
                auth.auth_middleware_files.append(file_entry.relative_path)

        if _EXPRESS_PASSPORT_PATTERN.search(content):
            auth.has_express_passport = True
            if file_entry.relative_path not in auth.auth_middleware_files:
                auth.auth_middleware_files.append(file_entry.relative_path)

        if _EXPRESS_JWT_PATTERN.search(content):
            auth.has_express_jwt = True
            if file_entry.relative_path not in auth.auth_middleware_files:
                auth.auth_middleware_files.append(file_entry.relative_path)

    return auth
