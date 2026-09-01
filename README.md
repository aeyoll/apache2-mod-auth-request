# mod_auth_request

nginx's `auth_request` for Apache 2.4: allow or deny a request based on the HTTP
status returned by another service.

Apache has no equivalent out of the box. `mod_authnz_fcgi` and
`mod_authnz_external` come closest, but they talk to a FastCGI application or run
a local program; neither asks a plain HTTP endpoint "may this request proceed?",
which is what forward-auth services (Authelia, oauth2-proxy, Vouch, or a portal
of your own) expect.

## How it works

nginx implements `auth_request` as a subrequest to an internal, proxied
location. This module does exactly the same thing with Apache's own subrequest
machinery, so the URI you point it at is resolved through the normal
configuration walk: put a `ProxyPass` on it and the check happens over HTTP.

```apache
<Location />
    AuthRequest /_auth
</Location>

<Location /_auth>
    ProxyPass http://127.0.0.1:8080/check
</Location>
```

Every request to `/` now triggers a `GET /check` on `127.0.0.1:8080`, and the
answer decides what happens next:

| Auth backend answers | Result                                                          |
| -------------------- | --------------------------------------------------------------- |
| 2xx                  | request proceeds                                                  |
| 401                  | 401, with the backend's `WWW-Authenticate`, or a redirect (below) |
| 403                  | 403                                                               |
| anything else        | 500, logged as an error                                           |

The auth backend's response body never reaches the client, and neither do its
headers apart from `WWW-Authenticate`. Only the status matters.

## Requirements

- Apache 2.4 with `mod_proxy` and `mod_proxy_http`
- `apache2-dev` (Debian/Ubuntu) or `httpd-devel` (RHEL/Fedora) to build

## Build and install

```sh
make
sudo make install
```

`make install` copies the module into Apache's module directory. Enable it the
way your distribution expects, for example on Debian/Ubuntu:

```sh
echo "LoadModule auth_request_module /usr/lib/apache2/modules/mod_auth_request.so" \
    | sudo tee /etc/apache2/mods-available/auth_request.load
sudo a2enmod auth_request proxy proxy_http
sudo systemctl restart apache2
```

## Directives

### AuthRequest

**Syntax:** `AuthRequest uri|off`
**Context:** server config, virtual host, directory, location

The local URI the authorization subrequest is sent to. It must start with `/`
and it must resolve to something that answers, in practice a location with a
`ProxyPass`. `off` disables a setting inherited from an enclosing scope.

### AuthRequestRedirect

**Syntax:** `AuthRequestRedirect url|off`
**Context:** server config, virtual host, directory, location

When the auth backend answers 401, redirect the client here with a 302 instead
of returning the 401. This is nginx's `error_page 401 = @portal; return 302`.
403 responses are unaffected: a 401 means "you are not logged in", which a login
portal can fix, while a 403 means "you may not have this", which it cannot.

The value accepts [expression syntax](https://httpd.apache.org/docs/2.4/expr.html),
so the portal can be told where to send the user back to:

```apache
AuthRequestRedirect "https://app.example.com/access?rd=%{escape:%{REQUEST_SCHEME}://%{HTTP_HOST}%{REQUEST_URI}}"
```

`%{REQUEST_URI}` is the path only; append `%{QUERY_STRING}` if you need the rest.

This cannot be done with `ErrorDocument`: Apache refuses a full URL in an
`ErrorDocument 401` ("cannot use a full URL in a 401 ErrorDocument directive"),
and a local `ErrorDocument` that answers with a redirect is treated as a
recursive error, which sends the original 401 to the client instead.

## What the auth backend receives

A `GET` on the subrequest URI, carrying the original request's headers (`Cookie`,
`Authorization`, `Host`, and the rest), with no request body, plus:

| Header              | Value                                              |
| ------------------- | -------------------------------------------------- |
| `X-Original-URI`    | the original request URI, query string included     |
| `X-Original-Method` | the original method                                 |
| `X-Forwarded-Proto` | `http` or `https`                                   |
| `X-Forwarded-For`   | client address (added by `mod_proxy`)               |
| `X-Forwarded-Host`  | original `Host` (added by `mod_proxy`)              |

The three `X-Original-*`/`X-Forwarded-Proto` values overwrite anything the client
sent under those names, so they cannot be spoofed.

## The nginx configuration, translated

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    location / {
        auth_request /_auth;
        error_page 401 = @access_portal;
        proxy_pass http://127.0.0.1:3000;
    }

    location = /_auth {
        internal;
        proxy_pass http://127.0.0.1:8080/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
    }

    location @access_portal {
        return 302 https://app.example.com/access;
    }

    location /access {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

becomes

```apache
<VirtualHost *:443>
    ServerName app.example.com

    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/app.example.com.pem
    SSLCertificateKeyFile /etc/ssl/private/app.example.com.key

    <Location />
        AuthRequest /_auth
        AuthRequestRedirect https://app.example.com/access

        ProxyPass        http://127.0.0.1:3000/
        ProxyPassReverse http://127.0.0.1:3000/
    </Location>

    # The authorization endpoint. Reachable as a subrequest only.
    <Location /_auth>
        AuthRequest off

        <If "%{IS_SUBREQ} == 'false'">
            Require all denied
        </If>

        ProxyPass http://127.0.0.1:8080/check
    </Location>

    # The portal itself must stay reachable without authorization.
    <Location /access>
        AuthRequest off

        ProxyPass        http://127.0.0.1:8080/access
        ProxyPassReverse http://127.0.0.1:8080/access
    </Location>
</VirtualHost>
```

Directive by directive:

| nginx                                                | Apache                                             |
| ---------------------------------------------------- | -------------------------------------------------- |
| `auth_request /_auth`                                | `AuthRequest /_auth`                                |
| `error_page 401` + `return 302`                      | `AuthRequestRedirect`                               |
| `internal`                                           | `<If "%{IS_SUBREQ} == 'false'"> Require all denied` |
| `proxy_pass_request_body off`, `Content-Length ""`   | nothing, subrequests never carry a body             |
| `proxy_set_header X-Real-IP $remote_addr`            | nothing, `mod_proxy` sends `X-Forwarded-For`        |
| `proxy_pass http://127.0.0.1:3000`                   | `ProxyPass` / `ProxyPassReverse`                    |

## Notes

**Protect the authorization endpoint.** The `<If>` block above is nginx's
`internal`: the location answers subrequests but not clients. Without it, anyone
can reach your auth backend through your virtual host.

**`Require` still applies.** Allowing a request only means this module has no
objection; any `Require` directives in scope are evaluated afterwards, as with
nginx's `satisfy all`.

**Subrequests are not checked**, which is what stops the authorization
subrequest from recursing into itself. This matches nginx, where the auth
location has its own configuration.

**One connection per check.** Apache never reuses a backend connection for a
subrequest (`mod_proxy_http` forces `Connection: close`), so every request opens
a fresh connection to the auth backend. That is fine for a service on localhost
and measurable over a network. Lifting it means replacing the subrequest with a
pooled HTTP client inside the module, which trades away the ability to configure
the backend with the usual `ProxyPass` machinery.

**Responses are not cached.** Every request is checked. If your auth backend is
slow, put the caching in the backend.

## Tests

```sh
make test
```

`test/smoke.sh` starts a throwaway Apache and a stub auth backend on ports 18080
and 18081, then checks each branch: allowed requests are served, 401 becomes a
redirect (or a 401 with the backend's challenge where no redirect is configured),
403 stays 403, an unexpected status fails closed with a 500, the auth endpoint
refuses direct hits, request bodies are not forwarded, `X-Original-*` cannot be
spoofed, and the auth backend's response body never leaks into the response.
