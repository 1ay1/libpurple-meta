/**
 * meta-http.c
 * 
 * HTTP abstraction layer implementation for libpurple-meta
 * Uses libsoup for HTTP requests (works with both libpurple 2.x and 3.x)
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#include "meta-http.h"
#include "../prpl-meta.h"

#include <glib.h>
#include <string.h>

#ifdef HAVE_LIBSOUP
#include <libsoup/soup.h>
#endif

/* Global soup session */
#ifdef HAVE_LIBSOUP
static SoupSession *http_session = NULL;
#endif

/* Context for tracking pending requests */
struct _MetaHttpContext {
    MetaHttpRequest *request;
    MetaHttpCallback callback;
    gpointer user_data;
    PurpleConnection *gc;
#ifdef HAVE_LIBSOUP
    SoupMessage *message;
    GCancellable *cancellable;
#endif
    gboolean cancelled;
};

/* ============================================================
 * Request Functions
 * ============================================================ */

MetaHttpRequest *meta_http_request_new(const char *url)
{
    MetaHttpRequest *request;
    
    if (!url) return NULL;
    
    request = g_new0(MetaHttpRequest, 1);
    request->url = g_strdup(url);
    request->method = g_strdup("GET");
    request->headers = g_hash_table_new_full(g_str_hash, g_str_equal, 
                                              g_free, g_free);
    request->timeout = 30;
    
    return request;
}

void meta_http_request_set_method(MetaHttpRequest *request, const char *method)
{
    if (!request || !method) return;
    
    g_free(request->method);
    request->method = g_strdup(method);
}

void meta_http_request_set_header(MetaHttpRequest *request,
                                   const char *name, const char *value)
{
    if (!request || !name || !value) return;
    
    g_hash_table_insert(request->headers, g_strdup(name), g_strdup(value));
}

void meta_http_request_set_body(MetaHttpRequest *request,
                                 const char *data, gssize len)
{
    if (!request) return;
    
    g_free(request->body);
    
    if (data) {
        if (len < 0) {
            len = strlen(data);
        }
        request->body = g_strndup(data, len);
        request->body_len = len;
    } else {
        request->body = NULL;
        request->body_len = 0;
    }
}

void meta_http_request_set_timeout(MetaHttpRequest *request, gint timeout_secs)
{
    if (!request) return;
    request->timeout = timeout_secs;
}

void meta_http_request_free(MetaHttpRequest *request)
{
    if (!request) return;
    
    g_free(request->url);
    g_free(request->method);
    g_free(request->body);
    if (request->headers) {
        g_hash_table_destroy(request->headers);
    }
    g_free(request);
}

/* ============================================================
 * Response Functions
 * ============================================================ */

static MetaHttpResponse *meta_http_response_new(void)
{
    MetaHttpResponse *response = g_new0(MetaHttpResponse, 1);
    response->headers = g_hash_table_new_full(g_str_hash, g_str_equal,
                                               g_free, g_free);
    return response;
}

gboolean meta_http_response_is_successful(MetaHttpResponse *response)
{
    if (!response) return FALSE;
    return response->success && 
           response->status_code >= 200 && 
           response->status_code < 300;
}

gint meta_http_response_get_code(MetaHttpResponse *response)
{
    if (!response) return 0;
    return response->status_code;
}

const gchar *meta_http_response_get_data(MetaHttpResponse *response, gsize *len)
{
    if (!response) {
        if (len) *len = 0;
        return NULL;
    }
    if (len) *len = response->data_len;
    return response->data;
}

const gchar *meta_http_response_get_header(MetaHttpResponse *response,
                                            const char *name)
{
    if (!response || !name || !response->headers) return NULL;
    return g_hash_table_lookup(response->headers, name);
}

const gchar *meta_http_response_get_error(MetaHttpResponse *response)
{
    if (!response) return NULL;
    return response->error;
}

void meta_http_response_free(MetaHttpResponse *response)
{
    if (!response) return;
    
    g_free(response->status_message);
    g_free(response->data);
    g_free(response->error);
    if (response->headers) {
        g_hash_table_destroy(response->headers);
    }
    g_free(response);
}

/* ============================================================
 * Context Functions
 * ============================================================ */

static void meta_http_context_free(MetaHttpContext *context)
{
    if (!context) return;
    
#ifdef HAVE_LIBSOUP
    if (context->cancellable) {
        g_object_unref(context->cancellable);
    }
#endif
    
    /* Note: request is freed separately after callback */
    g_free(context);
}

/* ============================================================
 * Initialization
 * ============================================================ */

gboolean meta_http_init(void)
{
#ifdef HAVE_LIBSOUP
    if (http_session) {
        return TRUE; /* Already initialized */
    }
    
    http_session = soup_session_new_with_options(
        "user-agent", "libpurple-meta/0.1.0",
        "timeout", 30,
        NULL
    );
    
    if (!http_session) {
        meta_error("Failed to create HTTP session");
        return FALSE;
    }
    
    meta_debug("HTTP subsystem initialized with libsoup");
    return TRUE;
#else
    meta_warning("HTTP subsystem: libsoup not available");
    return FALSE;
#endif
}

void meta_http_shutdown(void)
{
#ifdef HAVE_LIBSOUP
    if (http_session) {
        g_object_unref(http_session);
        http_session = NULL;
    }
    meta_debug("HTTP subsystem shut down");
#endif
}

/* ============================================================
 * Request Execution (libsoup implementation)
 * ============================================================ */

#ifdef HAVE_LIBSOUP

static void soup_request_callback(GObject *source_object,
                                   GAsyncResult *result,
                                   gpointer user_data)
{
    MetaHttpContext *context = (MetaHttpContext *)user_data;
    MetaHttpResponse *response;
    GError *error = NULL;
    GBytes *body_bytes;
    SoupMessage *msg = context->message;
    
    if (context->cancelled) {
        meta_http_request_free(context->request);
        meta_http_context_free(context);
        return;
    }
    
    response = meta_http_response_new();
    
    body_bytes = soup_session_send_and_read_finish(SOUP_SESSION(source_object),
                                                     result, &error);
    
    if (error) {
        response->success = FALSE;
        response->status_code = 0;
        response->error = g_strdup(error->message);
        g_error_free(error);
    } else {
        guint status_code = soup_message_get_status(msg);
        
        response->success = TRUE;
        response->status_code = status_code;
        response->status_message = g_strdup(soup_message_get_reason_phrase(msg));
        
        if (body_bytes) {
            gsize len;
            const gchar *data = g_bytes_get_data(body_bytes, &len);
            response->data = g_strndup(data, len);
            response->data_len = len;
            g_bytes_unref(body_bytes);
        }
        
        /* Copy response headers */
        SoupMessageHeaders *resp_headers = soup_message_get_response_headers(msg);
        SoupMessageHeadersIter iter;
        const char *name, *value;
        soup_message_headers_iter_init(&iter, resp_headers);
        while (soup_message_headers_iter_next(&iter, &name, &value)) {
            g_hash_table_insert(response->headers, g_strdup(name), g_strdup(value));
        }
    }
    
    /* Call user callback */
    if (context->callback) {
        context->callback(response, context->user_data);
    }
    
    /* Cleanup */
    meta_http_response_free(response);
    meta_http_request_free(context->request);
    g_object_unref(msg);
    meta_http_context_free(context);
}

MetaHttpContext *meta_http_request_execute(PurpleConnection *gc,
                                            MetaHttpRequest *request,
                                            MetaHttpCallback callback,
                                            gpointer user_data)
{
    MetaHttpContext *context;
    SoupMessage *msg;
    GHashTableIter iter;
    gpointer key, value;
    
    if (!request || !request->url) {
        meta_error("Invalid HTTP request");
        meta_http_request_free(request);
        return NULL;
    }
    
    if (!http_session) {
        if (!meta_http_init()) {
            meta_error("HTTP session not initialized");
            
            /* Call callback with error */
            if (callback) {
                MetaHttpResponse *resp = meta_http_response_new();
                resp->success = FALSE;
                resp->error = g_strdup("HTTP session not initialized");
                callback(resp, user_data);
                meta_http_response_free(resp);
            }
            
            meta_http_request_free(request);
            return NULL;
        }
    }
    
    /* Create soup message */
    msg = soup_message_new(request->method, request->url);
    if (!msg) {
        meta_error("Failed to create HTTP message for URL: %s", request->url);
        
        if (callback) {
            MetaHttpResponse *resp = meta_http_response_new();
            resp->success = FALSE;
            resp->error = g_strdup("Invalid URL");
            callback(resp, user_data);
            meta_http_response_free(resp);
        }
        
        meta_http_request_free(request);
        return NULL;
    }
    
    /* Set headers */
    SoupMessageHeaders *req_headers = soup_message_get_request_headers(msg);
    g_hash_table_iter_init(&iter, request->headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        soup_message_headers_append(req_headers, (const char *)key, (const char *)value);
    }
    
    /* Set body if present */
    if (request->body && request->body_len > 0) {
        GBytes *body_bytes = g_bytes_new(request->body, request->body_len);
        soup_message_set_request_body_from_bytes(msg, 
            g_hash_table_lookup(request->headers, "Content-Type"),
            body_bytes);
        g_bytes_unref(body_bytes);
    }
    
    /* Create context */
    context = g_new0(MetaHttpContext, 1);
    context->request = request;
    context->callback = callback;
    context->user_data = user_data;
    context->gc = gc;
    context->message = msg;
    context->cancellable = g_cancellable_new();
    context->cancelled = FALSE;
    
    /* Send request */
    soup_session_send_and_read_async(http_session, msg, G_PRIORITY_DEFAULT,
                                      context->cancellable,
                                      soup_request_callback, context);
    
    return context;
}

void meta_http_request_cancel(MetaHttpContext *context)
{
    if (!context) return;
    
    context->cancelled = TRUE;
    
    if (context->cancellable) {
        g_cancellable_cancel(context->cancellable);
    }
}

#else /* No libsoup */

MetaHttpContext *meta_http_request_execute(PurpleConnection *gc,
                                            MetaHttpRequest *request,
                                            MetaHttpCallback callback,
                                            gpointer user_data)
{
    meta_error("HTTP requests not available - libsoup not compiled in");
    
    if (callback) {
        MetaHttpResponse *resp = meta_http_response_new();
        resp->success = FALSE;
        resp->error = g_strdup("HTTP not available");
        callback(resp, user_data);
        meta_http_response_free(resp);
    }
    
    meta_http_request_free(request);
    return NULL;
}

void meta_http_request_cancel(MetaHttpContext *context)
{
    (void)context;
}

#endif /* HAVE_LIBSOUP */

/* ============================================================
 * Convenience Functions
 * ============================================================ */

MetaHttpContext *meta_http_get(PurpleConnection *gc, const char *url,
                                MetaHttpCallback callback, gpointer user_data)
{
    MetaHttpRequest *request = meta_http_request_new(url);
    if (!request) return NULL;
    
    return meta_http_request_execute(gc, request, callback, user_data);
}

MetaHttpContext *meta_http_post_json(PurpleConnection *gc, const char *url,
                                      const char *json_body,
                                      MetaHttpCallback callback,
                                      gpointer user_data)
{
    MetaHttpRequest *request = meta_http_request_new(url);
    if (!request) return NULL;
    
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_header(request, "Content-Type", "application/json");
    meta_http_request_set_body(request, json_body, -1);
    
    return meta_http_request_execute(gc, request, callback, user_data);
}

MetaHttpContext *meta_http_post_form(PurpleConnection *gc, const char *url,
                                      const char *form_data,
                                      MetaHttpCallback callback,
                                      gpointer user_data)
{
    MetaHttpRequest *request = meta_http_request_new(url);
    if (!request) return NULL;
    
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_header(request, "Content-Type", 
                                  "application/x-www-form-urlencoded");
    meta_http_request_set_body(request, form_data, -1);
    
    return meta_http_request_execute(gc, request, callback, user_data);
}