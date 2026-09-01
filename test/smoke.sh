#!/bin/sh
# End-to-end check for mod_auth_request: starts a throwaway apache2 and a stub
# auth backend, then exercises every branch of the status mapping.
set -eu

SRC=$(cd "$(dirname "$0")/.." && pwd)
MODULES=${MODULES:-/usr/lib/apache2/modules}
PORT=${PORT:-18080}
AUTH_PORT=${AUTH_PORT:-18081}
BASE="http://127.0.0.1:$PORT"
TMP=$(mktemp -d)

[ -f "$SRC/.libs/mod_auth_request.so" ] || { echo "run 'make' first"; exit 1; }

cleanup() {
    [ -f "$TMP/httpd.pid" ] && kill "$(cat "$TMP/httpd.pid")" 2>/dev/null || true
    [ -n "${BACKEND_PID:-}" ] && kill "$BACKEND_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $*"
    echo "--- apache error log ---"
    tail -n 20 "$TMP/error.log" 2>/dev/null || true
    echo "--- auth backend log ---"
    cat "$TMP/auth.log" 2>/dev/null || true
    exit 1
}

assert_eq() { [ "$2" = "$3" ] || fail "$1: expected '$3', got '$2'"; }

# Value of a response header, with the CR that curl -D keeps stripped off.
header() { tr -d '\r' < "$TMP/hdr" | sed -n "s/^$1: //p"; }

mkdir -p "$TMP/www"
echo PROTECTED > "$TMP/www/index.html"
echo PROTECTED > "$TMP/www/plain"
echo PROTECTED > "$TMP/www/literal"
: > "$TMP/auth.log"

cat > "$TMP/auth_backend.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = sys.argv[2]
BODY = b'AUTH-BACKEND-BODY'
VERDICTS = {'allow': 200, 'forbid': 403, 'teapot': 418}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open(LOG, 'a') as log:
            log.write('%s %s\n' % (self.command, self.path))
            for name, value in self.headers.items():
                log.write('  %s: %s\n' % (name.lower(), value))

        code = VERDICTS.get(self.headers.get('X-Test-Auth', ''), 401)
        self.send_response(code)
        if code == 401:
            self.send_header('WWW-Authenticate', 'Basic realm="stub"')
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    do_POST = do_GET

    def log_message(self, *args):
        pass


HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()
PY

cat > "$TMP/httpd.conf" <<CONF
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile "$TMP/httpd.pid"
DefaultRuntimeDir "$TMP"
ErrorLog "$TMP/error.log"
LogLevel info
DocumentRoot "$TMP/www"

LoadModule mpm_event_module $MODULES/mod_mpm_event.so
LoadModule authz_core_module $MODULES/mod_authz_core.so
LoadModule proxy_module $MODULES/mod_proxy.so
LoadModule proxy_http_module $MODULES/mod_proxy_http.so
LoadModule auth_request_module $SRC/.libs/mod_auth_request.so

<Directory "$TMP/www">
    Require all granted
</Directory>

<Location />
    AuthRequest /_auth
    AuthRequestRedirect "http://portal.example.com/access?rd=%{escape:%{REQUEST_URI}}"
</Location>

# Same protection, but the 401 is returned to the client as-is.
<Location /plain>
    AuthRequestRedirect off
</Location>

# A redirect target that is a plain URL rather than an expression.
<Location /literal>
    AuthRequestRedirect http://portal.example.com/access
</Location>

<Location /_auth>
    AuthRequest off
    <If "%{IS_SUBREQ} == 'false'">
        Require all denied
    </If>
    ProxyPass http://127.0.0.1:$AUTH_PORT/check
</Location>
CONF

python3 "$TMP/auth_backend.py" "$AUTH_PORT" "$TMP/auth.log" &
BACKEND_PID=$!
apache2 -f "$TMP/httpd.conf" -DFOREGROUND &

i=0
until curl -s -o /dev/null "http://127.0.0.1:$AUTH_PORT/check" || [ "$i" -ge 50 ]; do
    i=$((i + 1))
    sleep 0.2
done
[ "$i" -lt 50 ] || fail "auth backend did not come up on $AUTH_PORT"

i=0
until curl -s -o /dev/null "$BASE/" || [ "$i" -ge 50 ]; do
    i=$((i + 1))
    sleep 0.2
done
[ "$i" -lt 50 ] || fail "server did not come up on $PORT"

: > "$TMP/auth.log"

status=$(curl -s -o "$TMP/body" -w '%{http_code}' -H 'X-Test-Auth: allow' "$BASE/index.html")
assert_eq "allowed request" "$status" 200
assert_eq "allowed request body" "$(cat "$TMP/body")" PROTECTED

status=$(curl -s -o /dev/null -D "$TMP/hdr" -w '%{http_code}' "$BASE/index.html?a=b")
assert_eq "unauthorized request" "$status" 302
assert_eq "unauthorized redirect" "$(header Location)" \
    "http://portal.example.com/access?rd=/index.html"

status=$(curl -s -o /dev/null -D "$TMP/hdr" -w '%{http_code}' "$BASE/literal")
assert_eq "plain URL redirect" "$status" 302
assert_eq "plain URL redirect target" "$(header Location)" \
    "http://portal.example.com/access"

status=$(curl -s -o /dev/null -D "$TMP/hdr" -w '%{http_code}' "$BASE/plain")
assert_eq "401 passthrough" "$status" 401
assert_eq "401 challenge" "$(header WWW-Authenticate)" 'Basic realm="stub"'

status=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Test-Auth: forbid' "$BASE/index.html")
assert_eq "forbidden request" "$status" 403

status=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Test-Auth: teapot' "$BASE/index.html")
assert_eq "unexpected backend status" "$status" 500

: > "$TMP/auth.log"
status=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/_auth")
assert_eq "direct hit on the auth location" "$status" 403
[ ! -s "$TMP/auth.log" ] || fail "direct hit on the auth location reached the backend"

: > "$TMP/auth.log"
status=$(curl -s -o "$TMP/body" -w '%{http_code}' -H 'X-Test-Auth: allow' \
    -H 'X-Original-URI: /spoofed' -d 'secret=payload' "$BASE/index.html?q=1")
assert_eq "POST request" "$status" 200
grep -q '^GET /check$' "$TMP/auth.log" || fail "POST: auth subrequest was not a GET"
if grep -qi '^  content-length:' "$TMP/auth.log"; then
    fail "POST: request body was forwarded to the auth backend"
fi
grep -qi '^  x-original-uri: /index.html?q=1$' "$TMP/auth.log" ||
    fail "POST: X-Original-URI missing, wrong, or spoofed by the client"
grep -qi '^  x-original-method: POST$' "$TMP/auth.log" ||
    fail "POST: X-Original-Method missing or wrong"
grep -qi '^  x-forwarded-for: 127.0.0.1$' "$TMP/auth.log" ||
    fail "POST: X-Forwarded-For missing"

if grep -q AUTH-BACKEND-BODY "$TMP/body"; then
    fail "auth backend response body leaked into the client response"
fi

echo "OK: all checks passed"
