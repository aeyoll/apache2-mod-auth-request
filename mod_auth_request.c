/*
 * mod_auth_request - authorization based on the result of a subrequest,
 * modelled on nginx's ngx_http_auth_request_module.
 *
 * The subrequest is an ordinary Apache subrequest, so the URI it names is
 * resolved with the usual configuration walk: point it at a location that
 * mod_proxy handles and the check is performed over HTTP.
 */

#include "apr_buckets.h"
#include "apr_strings.h"

#include "ap_expr.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"

APLOG_USE_MODULE(auth_request);

#define DISCARD_FILTER_NAME "AUTH_REQUEST_DISCARD"

typedef struct {
    const char *uri; /* NULL when unset or explicitly "off" */
    ap_expr_info_t *redirect; /* NULL when unset or explicitly "off" */
    int is_set;
    int redirect_is_set;
} auth_request_conf;

static void *create_dir_conf(apr_pool_t *p, char *dir)
{
    return apr_pcalloc(p, sizeof(auth_request_conf));
}

static void *merge_dir_conf(apr_pool_t *p, void *basev, void *addv)
{
    auth_request_conf *base = basev;
    auth_request_conf *add = addv;
    auth_request_conf *conf = apr_pcalloc(p, sizeof(auth_request_conf));

    conf->uri = add->is_set ? add->uri : base->uri;
    conf->is_set = add->is_set || base->is_set;
    conf->redirect = add->redirect_is_set ? add->redirect : base->redirect;
    conf->redirect_is_set = add->redirect_is_set || base->redirect_is_set;

    return conf;
}

static const char *set_auth_request(cmd_parms *cmd, void *cfgv, const char *arg)
{
    auth_request_conf *conf = cfgv;

    if (!strcasecmp(arg, "off")) {
        conf->uri = NULL;
    }
    else if (arg[0] != '/') {
        return "AuthRequest takes a local URI path starting with '/', or 'off'";
    }
    else {
        conf->uri = arg;
    }
    conf->is_set = 1;

    return NULL;
}

static const char *set_auth_request_redirect(cmd_parms *cmd, void *cfgv,
                                             const char *arg)
{
    auth_request_conf *conf = cfgv;
    const char *err = NULL;

    if (!strcasecmp(arg, "off")) {
        conf->redirect = NULL;
    }
    else {
        conf->redirect = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
                                           &err, NULL);
        if (err) {
            return apr_pstrcat(cmd->pool, "Cannot parse AuthRequestRedirect '",
                               arg, "': ", err, (char *)NULL);
        }
    }
    conf->redirect_is_set = 1;

    return NULL;
}

/*
 * A subrequest shares the main request's output filter chain, so the auth
 * backend's response body would otherwise be written to the client. Response
 * headers cannot leak: ap_set_sub_req_protocol() sets assbackwards.
 */
static apr_status_t discard_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *e;

    for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e)) {
        const char *data;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(e)) {
            break;
        }
        if (APR_BUCKET_IS_METADATA(e)) {
            continue;
        }
        /* Read so that buckets still attached to the backend are consumed. */
        if (apr_bucket_read(e, &data, &len, APR_BLOCK_READ) != APR_SUCCESS) {
            break;
        }
    }
    apr_brigade_cleanup(bb);

    return APR_SUCCESS;
}

static int auth_request_check(request_rec *r)
{
    auth_request_conf *conf = ap_get_module_config(r->per_dir_config,
                                                   &auth_request_module);
    request_rec *rr;
    const char *challenge;
    int status;

    /*
     * Subrequests are never checked. That matches nginx, and it is what keeps
     * the auth subrequest itself from recursing back into this hook.
     */
    if (!conf->uri || r->main) {
        return DECLINED;
    }

    rr = ap_sub_req_method_uri("GET", conf->uri, r, r->output_filters);
    ap_add_output_filter(DISCARD_FILTER_NAME, NULL, rr, rr->connection);

    /*
     * The auth backend sees the subrequest, not the original one, so pass the
     * context it needs to decide. Overwrite rather than merge: a client must
     * not be able to describe its own request to the backend.
     * X-Forwarded-For and X-Forwarded-Host are added by mod_proxy itself.
     */
    apr_table_setn(rr->headers_in, "X-Original-URI", r->unparsed_uri);
    apr_table_setn(rr->headers_in, "X-Original-Method", r->method);
    apr_table_setn(rr->headers_in, "X-Forwarded-Proto", ap_http_scheme(r));

    /* A failed lookup (bad URI, denied by config) already carries its status. */
    if (rr->status == HTTP_OK) {
        int rv = ap_run_sub_req(rr);

        /*
         * Errors that never produced a response - an unreachable backend, for
         * one - are reported by the handler and leave rr->status untouched.
         */
        status = (rv == OK) ? rr->status : rv;
    }
    else {
        status = rr->status;
    }

    challenge = apr_table_get(rr->err_headers_out, "WWW-Authenticate");
    if (!challenge) {
        challenge = apr_table_get(rr->headers_out, "WWW-Authenticate");
    }
    if (challenge) {
        apr_table_setn(r->err_headers_out, "WWW-Authenticate",
                       apr_pstrdup(r->pool, challenge));
    }
    ap_destroy_sub_req(rr);

    if (status >= HTTP_OK && status < HTTP_MULTIPLE_CHOICES) {
        return OK;
    }

    /*
     * ErrorDocument cannot do this: a 401 ErrorDocument may not be a full URL,
     * and a local one that answers with a redirect is treated as a recursive
     * error, which sends the original 401 to the client instead.
     */
    if (status == HTTP_UNAUTHORIZED && conf->redirect) {
        const char *err = NULL;
        const char *url = ap_expr_str_exec(r, conf->redirect, &err);

        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "cannot evaluate AuthRequestRedirect: %s", err);

            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_table_setn(r->headers_out, "Location", url);

        return HTTP_MOVED_TEMPORARILY;
    }

    if (status == HTTP_UNAUTHORIZED || status == HTTP_FORBIDDEN) {
        return status;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "auth request %s returned unexpected status %d, denying %s",
                  conf->uri, status, r->uri);

    return HTTP_INTERNAL_SERVER_ERROR;
}

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter(DISCARD_FILTER_NAME, discard_filter, NULL,
                              AP_FTYPE_RESOURCE);
    ap_hook_access_checker(auth_request_check, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec auth_request_cmds[] = {
    AP_INIT_TAKE1("AuthRequest", set_auth_request, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "URI of the authorization subrequest, or 'off'"),
    AP_INIT_TAKE1("AuthRequestRedirect", set_auth_request_redirect, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "URL to redirect to when the auth request answers 401, "
                  "instead of returning the 401 (expression syntax allowed), "
                  "or 'off'"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA auth_request_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_conf,
    merge_dir_conf,
    NULL,
    NULL,
    auth_request_cmds,
    register_hooks
};
