"""
SkillSwap WSGI entry point.

Lets the existing http.server-based API run on any WSGI host
(PythonAnywhere, etc.) with ZERO changes to the route handlers.
Reuses server.ROUTES, server.ApiError, server.jdump directly.
"""
import io
from urllib.parse import urlparse
import server as API
import store as S
import seed as SEED

# Initialize + seed the database once at import (WSGI hosts reimport, not
# long-lived like http.server, so init must be idempotent — store.init_db
# uses CREATE TABLE IF NOT EXISTS and seed() is no-op-safe if data exists).
S.init_db()
SEED.seed()


class _Headers:
    """Dict-like header access over a WSGI environ, mimicking
    BaseHTTPRequestHandler.headers.get(Title-Case-Name)."""
    def __init__(self, environ):
        self._env = environ

    def get(self, key, default=None):
        name = key.upper().replace("-", "_")
        if name in ("CONTENT_LENGTH", "CONTENT_TYPE"):
            return self._env.get(name, default)
        return self._env.get("HTTP_" + name, default)


class _FakeHandler:
    """Stands in for BaseHTTPRequestHandler so route functions
    (parse_body, require_user, ...) work unchanged."""
    def __init__(self, environ):
        self.headers = _Headers(environ)
        self.path = environ.get("PATH_INFO", "/") + (
            "?" + environ["QUERY_STRING"] if environ.get("QUERY_STRING") else ""
        )
        self.command = environ.get("REQUEST_METHOD", "GET")
        stream = environ.get("wsgi.input")
        self.rfile = stream if stream is not None else io.BytesIO(b"")


def _cors():
    return [
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS"),
        ("Access-Control-Allow-Headers", "Content-Type, Authorization"),
    ]


def application(environ, start_response):
    h = _FakeHandler(environ)
    method = h.command
    if method == "OPTIONS":
        start_response("204 No Content", _cors())
        return [b""]
    path = urlparse(h.path).path
    for (m, rx, fn) in API.ROUTES:
        match = rx.match(path)
        if match and m == method:
            try:
                result = fn(h, match)
                body = result if isinstance(result, (bytes, bytearray)) else API.jdump(result)
                start_response("200 OK", _cors() + [("Content-Type", "application/json")])
                return [body]
            except API.ApiError as e:
                body = API.jdump({"error": e.msg})
                start_response("%d Error" % e.code, _cors() + [("Content-Type", "application/json")])
                return [body]
            except Exception as e:
                import traceback; traceback.print_exc()
                body = API.jdump({"error": "Server error: %s" % e})
                start_response("500 Internal Server Error", _cors() + [("Content-Type", "application/json")])
                return [body]
    start_response("404 Not Found", _cors() + [("Content-Type", "application/json")])
    return [API.jdump({"error": "Not found"})]


# For local testing:  python wsgi.py
if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    port = int(__import__("os").environ.get("PORT", "8000"))
    print("SkillSwap WSGI listening on :%d" % port)
    make_server("0.0.0.0", port, application).serve_forever()
