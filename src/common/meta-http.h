/**
 * meta-http.h
 * 
 * HTTP abstraction layer for libpurple-meta
 * Provides a unified HTTP API that works with both libpurple 2.x and 3.x
 * 
 * For libpurple 2.x: Uses libsoup 3.0 directly
 * For libpurple 3.x: Uses native PurpleHttp* API
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef META_HTTP_H
#define META_HTTP_H

#include <glib.h>
#include <purple.h>

/* Detect purple version */
#ifndef PURPLE_VERSION
#  if defined(PURPLE_MAJOR_VERSION) && PURPLE_MAJOR_VERSION >= 3
#    define PURPLE_VERSION 3
#  else
#    define PURPLE_VERSION 2
#  endif
#endif

/* Forward declarations */
typedef struct _MetaHttpRequest MetaHttpRequest;
typedef struct _MetaHttpResponse MetaHttpResponse;
typedef struct _MetaHttpContext MetaHttpContext;

/**
 * HTTP callback function type
 */
typedef void (*MetaHttpCallback)(MetaHttpResponse *response, gpointer user_data);

/**
 * MetaHttpRequest - HTTP request structure
 */
struct _MetaHttpRequest {
    gchar *url;
    gchar *method;
    GHashTable *headers;
    gchar *body;
    gsize body_len;
    gint timeout;
};

/**
 * MetaHttpResponse - HTTP response structure
 */
struct _MetaHttpResponse {
    gboolean success;
    gint status_code;
    gchar *status_message;
    GHashTable *headers;
    gchar *data;
    gsize data_len;
    gchar *error;
};

/* ============================================================
 * Request Functions
 * ============================================================ */

/**
 * Create a new HTTP request
 * 
 * @param url Target URL
 * @return New request (caller must free with meta_http_request_free)
 */
MetaHttpRequest *meta_http_request_new(const char *url);

/**
 * Set request method (GET, POST, PUT, DELETE, etc.)
 * 
 * @param request The request
 * @param method HTTP method
 */
void meta_http_request_set_method(MetaHttpRequest *request, const char *method);

/**
 * Set a request header
 * 
 * @param request The request
 * @param name Header name
 * @param value Header value
 */
void meta_http_request_set_header(MetaHttpRequest *request, 
                                   const char *name, const char *value);

/**
 * Set request body
 * 
 * @param request The request
 * @param data Body data
 * @param len Data length (-1 for strlen)
 */
void meta_http_request_set_body(MetaHttpRequest *request, 
                                 const char *data, gssize len);

/**
 * Set request timeout
 * 
 * @param request The request
 * @param timeout_secs Timeout in seconds
 */
void meta_http_request_set_timeout(MetaHttpRequest *request, gint timeout_secs);

/**
 * Free a request
 * 
 * @param request The request to free
 */
void meta_http_request_free(MetaHttpRequest *request);

/* ============================================================
 * Response Functions
 * ============================================================ */

/**
 * Check if response was successful (2xx status code)
 * 
 * @param response The response
 * @return TRUE if successful
 */
gboolean meta_http_response_is_successful(MetaHttpResponse *response);

/**
 * Get HTTP status code
 * 
 * @param response The response
 * @return Status code (e.g., 200, 404)
 */
gint meta_http_response_get_code(MetaHttpResponse *response);

/**
 * Get response body data
 * 
 * @param response The response
 * @param len Output: data length (can be NULL)
 * @return Response data (owned by response, do not free)
 */
const gchar *meta_http_response_get_data(MetaHttpResponse *response, gsize *len);

/**
 * Get a response header
 * 
 * @param response The response
 * @param name Header name
 * @return Header value or NULL
 */
const gchar *meta_http_response_get_header(MetaHttpResponse *response, 
                                            const char *name);

/**
 * Get error message (if any)
 * 
 * @param response The response
 * @return Error message or NULL
 */
const gchar *meta_http_response_get_error(MetaHttpResponse *response);

/**
 * Free a response
 * 
 * @param response The response to free
 */
void meta_http_response_free(MetaHttpResponse *response);

/* ============================================================
 * Execution Functions
 * ============================================================ */

/**
 * Initialize HTTP subsystem
 * Call once at plugin load
 * 
 * @return TRUE if successful
 */
gboolean meta_http_init(void);

/**
 * Shutdown HTTP subsystem
 * Call once at plugin unload
 */
void meta_http_shutdown(void);

/**
 * Execute an HTTP request asynchronously
 * 
 * @param gc Purple connection (for account context)
 * @param request The request to execute
 * @param callback Function to call with response
 * @param user_data Data to pass to callback
 * @return Context handle (can be used to cancel)
 */
MetaHttpContext *meta_http_request_execute(PurpleConnection *gc,
                                            MetaHttpRequest *request,
                                            MetaHttpCallback callback,
                                            gpointer user_data);

/**
 * Cancel a pending HTTP request
 * 
 * @param context Context returned by meta_http_request_execute
 */
void meta_http_request_cancel(MetaHttpContext *context);

/* ============================================================
 * Convenience Functions
 * ============================================================ */

/**
 * Perform a simple GET request
 * 
 * @param gc Purple connection
 * @param url URL to fetch
 * @param callback Response callback
 * @param user_data Callback data
 * @return Context handle
 */
MetaHttpContext *meta_http_get(PurpleConnection *gc, const char *url,
                                MetaHttpCallback callback, gpointer user_data);

/**
 * Perform a POST request with JSON body
 * 
 * @param gc Purple connection
 * @param url URL to post to
 * @param json_body JSON string
 * @param callback Response callback
 * @param user_data Callback data
 * @return Context handle
 */
MetaHttpContext *meta_http_post_json(PurpleConnection *gc, const char *url,
                                      const char *json_body,
                                      MetaHttpCallback callback, 
                                      gpointer user_data);

/**
 * Perform a POST request with form data
 * 
 * @param gc Purple connection
 * @param url URL to post to
 * @param form_data Form data (key=value&...)
 * @param callback Response callback
 * @param user_data Callback data
 * @return Context handle
 */
MetaHttpContext *meta_http_post_form(PurpleConnection *gc, const char *url,
                                      const char *form_data,
                                      MetaHttpCallback callback,
                                      gpointer user_data);

/* ============================================================
 * Compatibility Macros
 * 
 * These allow existing code using purple_http_* to work
 * ============================================================ */

#if PURPLE_VERSION == 2

/* Map purple_http_* to meta_http_* */
#define PurpleHttpRequest   MetaHttpRequest
#define PurpleHttpResponse  MetaHttpResponse
#define PurpleHttpConnection MetaHttpContext

#define purple_http_request_new(url) \
    meta_http_request_new(url)

#define purple_http_request_set_method(req, method) \
    meta_http_request_set_method(req, method)

#define purple_http_request_header_set(req, name, value) \
    meta_http_request_set_header(req, name, value)

#define purple_http_request_set_contents(req, data, len) \
    meta_http_request_set_body(req, data, len)

#define purple_http_request_unref(req) \
    /* Request is freed after callback, do nothing */

#define purple_http_request(gc, req, callback, user_data) \
    meta_http_request_execute(gc, req, (MetaHttpCallback)(callback), user_data)

#define purple_http_response_is_successful(resp) \
    meta_http_response_is_successful((MetaHttpResponse*)(resp))

#define purple_http_response_get_code(resp) \
    meta_http_response_get_code((MetaHttpResponse*)(resp))

#define purple_http_response_get_data(resp, len) \
    meta_http_response_get_data((MetaHttpResponse*)(resp), len)

#endif /* PURPLE_VERSION == 2 */

#endif /* META_HTTP_H */