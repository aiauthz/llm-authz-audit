"""Tests for AuthContext cross-file auth tracking."""

from llm_authz_audit.analyzers.auth_context import AuthContext, build_auth_context


class TestAuthContext:
    def test_has_project_auth_false_by_default(self):
        ctx = AuthContext()
        assert not ctx.has_project_auth

    def test_has_project_auth_with_fastapi(self):
        ctx = AuthContext(has_fastapi_depends=True)
        assert ctx.has_project_auth

    def test_summary_empty(self):
        ctx = AuthContext()
        assert ctx.summary == "none"

    def test_summary_with_values(self):
        ctx = AuthContext(has_fastapi_depends=True, has_oauth2_bearer=True)
        assert "FastAPI Depends()" in ctx.summary
        assert "OAuth2 Bearer" in ctx.summary


class TestBuildAuthContext:
    def test_detects_fastapi_depends(self, make_scan_context):
        ctx = make_scan_context({
            "auth.py": 'from fastapi import Depends\ndef endpoint(user=Depends(get_user)): pass\n',
            "app.py": 'x = 1\n',
        })
        auth = build_auth_context(ctx)
        assert auth.has_fastapi_depends
        assert "auth.py" in auth.auth_middleware_files

    def test_detects_oauth2_bearer(self, make_scan_context):
        ctx = make_scan_context({
            "deps.py": 'from fastapi.security import OAuth2PasswordBearer\noauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")\n',
        })
        auth = build_auth_context(ctx)
        assert auth.has_oauth2_bearer

    def test_detects_flask_login(self, make_scan_context):
        ctx = make_scan_context({
            "views.py": '@login_required\ndef protected(): pass\n',
        })
        auth = build_auth_context(ctx)
        assert auth.has_flask_login_required

    def test_detects_before_request(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": '@app.before_request\ndef check_auth(): pass\n',
        })
        auth = build_auth_context(ctx)
        assert auth.has_before_request_handler

    def test_detects_express_passport(self, make_scan_context):
        ctx = make_scan_context({
            "auth.js": 'const passport = require("passport");\npassport.initialize();\n',
        })
        auth = build_auth_context(ctx)
        assert auth.has_express_passport

    def test_detects_express_jwt(self, make_scan_context):
        ctx = make_scan_context({
            "middleware.ts": 'import jwt from "jsonwebtoken";\njwt.verify(token, secret);\n',
        })
        auth = build_auth_context(ctx)
        assert auth.has_express_jwt

    def test_no_auth_detected(self, make_scan_context):
        ctx = make_scan_context({
            "app.py": 'x = 1\n',
            "utils.py": 'def helper(): pass\n',
        })
        auth = build_auth_context(ctx)
        assert not auth.has_project_auth
        assert auth.summary == "none"

    def test_summary_includes_files(self, make_scan_context):
        ctx = make_scan_context({
            "auth.py": 'from fastapi import Depends\ndef ep(u=Depends(get_user)): pass\n',
        })
        auth = build_auth_context(ctx)
        assert "auth.py" in auth.summary
