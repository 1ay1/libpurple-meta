/**
 * meta-auth.c
 * 
 * OAuth authentication module implementation for libpurple-meta
 * Handles Meta (Facebook/Instagram) OAuth 2.0 flow and token management
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#include "meta-auth.h"
#include "meta-config.h"
#include "meta-security.h"
#include <json-glib/json-glib.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * Internal State Management
 * ============================================================ */

static GHashTable *pending_auth_states = NULL;

static void ensure_auth_states_init(void)
{
    if (!pending_auth_states) {
        pending_auth_states = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                     g_free, NULL);
    }
}

/* ============================================================
 * Helper Functions
 * ============================================================ */

gchar *meta_auth_generate_state(void)
{
    guint8 random_bytes[32];
    GString *state = g_string_new(NULL);
    
    /* Generate random bytes */
    for (int i = 0; i < 32; i++) {
        random_bytes[i] = g_random_int_range(0, 256);
    }
    
    /* Convert to hex string */
    for (int i = 0; i < 32; i++) {
        g_string_append_printf(state, "%02x", random_bytes[i]);
    }
    
    return g_string_free(state, FALSE);
}

void meta_auth_generate_pkce(gchar **verifier, gchar **challenge)
{
    guint8 random_bytes[32];
    GString *verifier_str = g_string_new(NULL);
    GChecksum *checksum;
    guint8 digest[32];
    gsize digest_len = 32;
    
    /* Generate code verifier (base64url of random bytes) */
    for (int i = 0; i < 32; i++) {
        random_bytes[i] = g_random_int_range(0, 256);
    }
    
    gchar *base64 = g_base64_encode(random_bytes, 32);
    
    /* Convert to base64url (replace + with -, / with _, remove =) */
    for (char *p = base64; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = '\0'; break; }
    }
    
    *verifier = base64;
    
    /* Generate code challenge (SHA256 of verifier, then base64url) */
    checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (guchar *)base64, strlen(base64));
    g_checksum_get_digest(checksum, digest, &digest_len);
    g_checksum_free(checksum);
    
    gchar *challenge_base64 = g_base64_encode(digest, digest_len);
    
    /* Convert to base64url */
    for (char *p = challenge_base64; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = '\0'; break; }
    }
    
    *challenge = challenge_base64;
}

gchar *meta_auth_build_auth_url(MetaAccount *account,
                                 const char *state,
                                 const char *code_challenge)
{
    const gchar *auth_url;
    GString *url;
    const char *scope;
    
    /* Get OAuth URL from config or use default */
    auth_url = meta_config_get_oauth_auth_url();
    if (!auth_url || auth_url[0] == '\0') {
        auth_url = META_OAUTH_AUTH_URL;
    }
    
    url = g_string_new(auth_url);
    
    /* Determine scope based on service mode */
    switch (account->mode) {
        case META_SERVICE_INSTAGRAM:
            scope = META_OAUTH_SCOPE_INSTAGRAM;
            break;
        case META_SERVICE_UNIFIED:
            scope = META_OAUTH_SCOPE_MESSENGER "," META_OAUTH_SCOPE_INSTAGRAM;
            break;
        case META_SERVICE_MESSENGER:
        default:
            scope = META_OAUTH_SCOPE_MESSENGER;
            break;
    }
    
    g_string_append_printf(url, "?client_id=%s", META_OAUTH_CLIENT_ID);
    
    gchar *encoded_redirect = g_uri_escape_string(META_OAUTH_REDIRECT_URI, NULL, TRUE);
    g_string_append_printf(url, "&redirect_uri=%s", encoded_redirect);
    g_free(encoded_redirect);
    
    g_string_append_printf(url, "&state=%s", state);
    
    gchar *encoded_scope = g_uri_escape_string(scope, NULL, TRUE);
    g_string_append_printf(url, "&scope=%s", encoded_scope);
    g_free(encoded_scope);
    
    g_string_append(url, "&response_type=code");
    
    if (code_challenge) {
        g_string_append_printf(url, "&code_challenge=%s", code_challenge);
        g_string_append(url, "&code_challenge_method=S256");
    }
    
    return g_string_free(url, FALSE);
}

gboolean meta_auth_open_browser(const char *auth_url)
{
    GError *error = NULL;
    gboolean success;
    
#ifdef _WIN32
    /* Windows: use ShellExecute equivalent via glib */
    gchar *command = g_strdup_printf("start \"\" \"%s\"", auth_url);
    success = g_spawn_command_line_async(command, &error);
    g_free(command);
#elif defined(__APPLE__)
    /* macOS */
    gchar *command = g_strdup_printf("open \"%s\"", auth_url);
    success = g_spawn_command_line_async(command, &error);
    g_free(command);
#else
    /* Linux/Unix - try xdg-open */
    gchar *command = g_strdup_printf("xdg-open \"%s\"", auth_url);
    success = g_spawn_command_line_async(command, &error);
    g_free(command);
#endif
    
    if (!success && error) {
        meta_warning("Failed to open browser: %s", error->message);
        g_error_free(error);
    }
    
    return success;
}

/* ============================================================
 * OAuth Flow Implementation
 * ============================================================ */

void meta_auth_start_oauth(MetaAccount *account)
{
    meta_auth_start_oauth_async(account, NULL, NULL);
}

void meta_auth_start_oauth_async(MetaAccount *account,
                                  MetaAuthCallback callback,
                                  gpointer user_data)
{
    MetaAuthState *state;
    gchar *auth_url;
    
    ensure_auth_states_init();
    
    /* Create auth state */
    state = g_new0(MetaAuthState, 1);
    state->account = account;
    state->state = meta_auth_generate_state();
    state->callback = callback;
    state->user_data = user_data;
    
    /* Generate PKCE parameters */
    meta_auth_generate_pkce(&state->code_verifier, &state->code_challenge);
    
    /* Store state for later lookup */
    g_hash_table_insert(pending_auth_states, g_strdup(state->state), state);
    
    /* Build auth URL */
    auth_url = meta_auth_build_auth_url(account, state->state, state->code_challenge);
    
    meta_debug("Starting OAuth flow, opening: %s", auth_url);
    
    /* Update connection status */
    purple_connection_update_progress(account->pc, "Opening browser for login...",
                                       1, 3);
    
    /* Try to open browser */
    if (!meta_auth_open_browser(auth_url)) {
        /* Browser failed, show URL to user */
        purple_notify_uri(account->pc, auth_url);
        
        /* Also show a message with the URL */
        purple_notify_message(account->pc, PURPLE_NOTIFY_MSG_INFO,
                              "Meta Authentication",
                              "Please open this URL in your browser to login:",
                              auth_url, NULL, NULL);
    }
    
    /* Set up a timeout for the auth flow (5 minutes) */
    state->timeout_handle = g_timeout_add_seconds(300, 
        (GSourceFunc)meta_auth_timeout_cb, state);
    
    /* Start local HTTP server for OAuth callback */
    meta_auth_start_callback_server(state);
    
    g_free(auth_url);
}

static gboolean meta_auth_timeout_cb(MetaAuthState *state)
{
    meta_warning("OAuth flow timed out");
    
    /* Clean up */
    if (state->callback) {
        state->callback(state->account, FALSE, "Authentication timed out", 
                       state->user_data);
    }
    
    purple_connection_error(state->account->pc,
                           PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                           "Authentication timed out. Please try again.");
    
    meta_auth_state_free(state);
    
    return G_SOURCE_REMOVE;
}

static void meta_auth_start_callback_server(MetaAuthState *state)
{
    GError *error = NULL;
    GSocketService *service;
    
    service = g_socket_service_new();
    
    /* Try to listen on a random available port */
    state->http_port = g_socket_listener_add_any_inet_port(
        G_SOCKET_LISTENER(service), NULL, &error);
    
    if (error) {
        meta_warning("Failed to start callback server: %s", error->message);
        g_error_free(error);
        return;
    }
    
    /* Connect handler for incoming connections */
    g_signal_connect(service, "incoming",
                     G_CALLBACK(meta_auth_handle_http_connection), state);
    
    g_socket_service_start(service);
    state->http_server = service;
    
    meta_debug("OAuth callback server listening on port %d", state->http_port);
}

static gboolean meta_auth_handle_http_connection(GSocketService *service,
                                                  GSocketConnection *connection,
                                                  GObject *source_object,
                                                  MetaAuthState *state)
{
    GInputStream *input;
    GOutputStream *output;
    gchar buffer[4096];
    gssize bytes_read;
    gchar *auth_code = NULL;
    gchar *error_msg = NULL;
    gchar *response_state = NULL;
    
    input = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    output = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    
    /* Read HTTP request */
    bytes_read = g_input_stream_read(input, buffer, sizeof(buffer) - 1, NULL, NULL);
    if (bytes_read <= 0) {
        return TRUE;
    }
    buffer[bytes_read] = '\0';
    
    /* Parse the request URL for parameters */
    gchar *query_start = strchr(buffer, '?');
    if (query_start) {
        gchar *query_end = strchr(query_start, ' ');
        if (query_end) {
            *query_end = '\0';
        }
        
        /* Parse query parameters */
        gchar **params = g_strsplit(query_start + 1, "&", -1);
        for (int i = 0; params[i]; i++) {
            gchar **kv = g_strsplit(params[i], "=", 2);
            if (kv[0] && kv[1]) {
                if (g_strcmp0(kv[0], "code") == 0) {
                    auth_code = g_uri_unescape_string(kv[1], NULL);
                } else if (g_strcmp0(kv[0], "state") == 0) {
                    response_state = g_uri_unescape_string(kv[1], NULL);
                } else if (g_strcmp0(kv[0], "error") == 0) {
                    error_msg = g_uri_unescape_string(kv[1], NULL);
                }
            }
            g_strfreev(kv);
        }
        g_strfreev(params);
    }
    
    /* Send response to browser */
    const char *html_response;
    if (auth_code && g_strcmp0(response_state, state->state) == 0) {
        html_response = 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<!DOCTYPE html><html><body>"
            "<h1>Authentication Successful!</h1>"
            "<p>You can close this window and return to Pidgin.</p>"
            "</body></html>";
    } else {
        html_response = 
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<!DOCTYPE html><html><body>"
            "<h1>Authentication Failed</h1>"
            "<p>Please try again.</p>"
            "</body></html>";
    }
    
    g_output_stream_write_all(output, html_response, strlen(html_response),
                              NULL, NULL, NULL);
    
    /* Process the auth callback */
    if (auth_code && g_strcmp0(response_state, state->state) == 0) {
        meta_auth_handle_callback(state, auth_code, NULL);
    } else if (error_msg) {
        meta_auth_handle_callback(state, NULL, error_msg);
    } else {
        meta_auth_handle_callback(state, NULL, "Invalid callback parameters");
    }
    
    g_free(auth_code);
    g_free(error_msg);
    g_free(response_state);
    
    return TRUE;
}

void meta_auth_handle_callback(MetaAuthState *state,
                                const char *auth_code,
                                const char *error)
{
    /* Cancel timeout */
    if (state->timeout_handle) {
        g_source_remove(state->timeout_handle);
        state->timeout_handle = 0;
    }
    
    /* Stop callback server */
    if (state->http_server) {
        g_socket_service_stop(G_SOCKET_SERVICE(state->http_server));
        g_object_unref(state->http_server);
        state->http_server = NULL;
    }
    
    /* Remove from pending states */
    g_hash_table_remove(pending_auth_states, state->state);
    
    if (error) {
        meta_error("OAuth error: %s", error);
        
        if (state->callback) {
            state->callback(state->account, FALSE, error, state->user_data);
        }
        
        purple_connection_error(state->account->pc,
                               PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                               error);
        
        meta_auth_state_free(state);
        return;
    }
    
    if (!auth_code) {
        meta_error("No authorization code received");
        
        if (state->callback) {
            state->callback(state->account, FALSE, "No authorization code",
                           state->user_data);
        }
        
        purple_connection_error(state->account->pc,
                               PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                               "No authorization code received");
        
        meta_auth_state_free(state);
        return;
    }
    
    meta_debug("Received authorization code, exchanging for token...");
    
    purple_connection_update_progress(state->account->pc, 
                                       "Exchanging authorization code...",
                                       2, 3);
    
    /* Exchange code for token */
    meta_auth_exchange_code(state->account, auth_code,
                            meta_auth_exchange_complete_cb, state);
}

static void meta_auth_exchange_complete_cb(MetaAccount *account,
                                            MetaOAuthToken *token,
                                            const char *error_message,
                                            gpointer user_data)
{
    MetaAuthState *state = user_data;
    
    if (error_message || !token) {
        meta_error("Token exchange failed: %s", 
                   error_message ? error_message : "Unknown error");
        
        if (state->callback) {
            state->callback(account, FALSE, error_message, state->user_data);
        }
        
        purple_connection_error(account->pc,
                               PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                               error_message ? error_message : "Token exchange failed");
        
        meta_auth_state_free(state);
        return;
    }
    
    meta_debug("Token exchange successful!");
    
    /* Store the token */
    meta_auth_store_token(account, token);
    
    /* Update account state */
    account->access_token = g_strdup(token->access_token);
    account->user_id = g_strdup(token->user_id);
    account->token_expiry = token->expires_at;
    
    /* Call the callback */
    if (state->callback) {
        state->callback(account, TRUE, NULL, state->user_data);
    }
    
    /* Connect to services */
    purple_connection_update_progress(account->pc, "Connecting...", 3, 3);
    meta_websocket_connect(account);
    
    meta_oauth_token_free(token);
    meta_auth_state_free(state);
}

void meta_auth_exchange_code(MetaAccount *account,
                              const char *auth_code,
                              MetaTokenCallback callback,
                              gpointer user_data)
{
    GString *post_data = g_string_new(NULL);
    PurpleHttpRequest *request;
    
    /* Build POST data */
    g_string_append_printf(post_data, "client_id=%s", META_OAUTH_CLIENT_ID);
    
    gchar *encoded_redirect = g_uri_escape_string(META_OAUTH_REDIRECT_URI, NULL, TRUE);
    g_string_append_printf(post_data, "&redirect_uri=%s", encoded_redirect);
    g_free(encoded_redirect);
    
    gchar *encoded_code = g_uri_escape_string(auth_code, NULL, TRUE);
    g_string_append_printf(post_data, "&code=%s", encoded_code);
    g_free(encoded_code);
    
    g_string_append(post_data, "&grant_type=authorization_code");
    
    /* Note: In production, client_secret should be handled securely */
    /* For PKCE flow, we'd include the code_verifier instead */
    
    /* Create HTTP request using config URL */
    const gchar *token_url = meta_config_get_oauth_token_url();
    if (!token_url || token_url[0] == '\0') {
        token_url = META_OAUTH_TOKEN_URL;
    }
    request = purple_http_request_new(token_url);
    purple_http_request_set_method(request, "POST");
    purple_http_request_header_set(request, "Content-Type", 
                                    "application/x-www-form-urlencoded");
    purple_http_request_set_contents(request, post_data->str, post_data->len);
    
    /* Create callback data */
    MetaTokenExchangeData *data = g_new0(MetaTokenExchangeData, 1);
    data->account = account;
    data->callback = callback;
    data->user_data = user_data;
    
    /* Make the request */
    purple_http_request(account->pc, request, meta_auth_token_response_cb, data);
    
    purple_http_request_unref(request);
    g_string_free(post_data, TRUE);
}

typedef struct {
    MetaAccount *account;
    MetaTokenCallback callback;
    gpointer user_data;
} MetaTokenExchangeData;

static void meta_auth_token_response_cb(PurpleHttpConnection *connection,
                                         PurpleHttpResponse *response,
                                         gpointer user_data)
{
    MetaTokenExchangeData *data = user_data;
    JsonParser *parser = NULL;
    JsonObject *root;
    MetaOAuthToken *token = NULL;
    const gchar *response_data;
    gsize response_len;
    GError *error = NULL;
    
    if (!purple_http_response_is_successful(response)) {
        int code = purple_http_response_get_code(response);
        gchar *error_msg = g_strdup_printf("HTTP error %d", code);
        
        if (data->callback) {
            data->callback(data->account, NULL, error_msg, data->user_data);
        }
        
        g_free(error_msg);
        g_free(data);
        return;
    }
    
    response_data = purple_http_response_get_data(response, &response_len);
    
    /* Parse JSON response */
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, response_data, response_len, &error)) {
        meta_error("Failed to parse token response: %s", error->message);
        
        if (data->callback) {
            data->callback(data->account, NULL, error->message, data->user_data);
        }
        
        g_error_free(error);
        g_object_unref(parser);
        g_free(data);
        return;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    
    /* Check for error in response */
    if (json_object_has_member(root, "error")) {
        JsonObject *error_obj = json_object_get_object_member(root, "error");
        const gchar *error_msg = json_object_get_string_member(error_obj, "message");
        
        if (data->callback) {
            data->callback(data->account, NULL, error_msg, data->user_data);
        }
        
        g_object_unref(parser);
        g_free(data);
        return;
    }
    
    /* Extract token data */
    token = g_new0(MetaOAuthToken, 1);
    token->access_token = g_strdup(json_object_get_string_member(root, "access_token"));
    token->token_type = g_strdup(json_object_get_string_member_with_default(root, "token_type", "bearer"));
    
    if (json_object_has_member(root, "expires_in")) {
        gint64 expires_in = json_object_get_int_member(root, "expires_in");
        token->expires_at = time(NULL) + expires_in;
    } else {
        /* Default to 60 days if not specified */
        token->expires_at = time(NULL) + (60 * 24 * 60 * 60);
    }
    
    if (json_object_has_member(root, "user_id")) {
        token->user_id = g_strdup(json_object_get_string_member(root, "user_id"));
    }
    
    /* Call callback with token */
    if (data->callback) {
        data->callback(data->account, token, NULL, data->user_data);
    }
    
    g_object_unref(parser);
    g_free(data);
}

void meta_auth_cancel(MetaAuthState *state)
{
    if (!state) return;
    
    /* Remove from pending states */
    if (state->state) {
        g_hash_table_remove(pending_auth_states, state->state);
    }
    
    /* Cancel timeout */
    if (state->timeout_handle) {
        g_source_remove(state->timeout_handle);
    }
    
    /* Stop HTTP server */
    if (state->http_server) {
        g_socket_service_stop(G_SOCKET_SERVICE(state->http_server));
        g_object_unref(state->http_server);
    }
    
    meta_auth_state_free(state);
}

/* ============================================================
 * Token Management
 * ============================================================ */

gboolean meta_auth_validate_token(MetaAccount *account)
{
    /* Quick check: is token present? */
    if (!account->access_token || strlen(account->access_token) == 0) {
        return FALSE;
    }
    
    /* Quick check: is token expired? */
    if (account->token_expiry > 0 && account->token_expiry < time(NULL)) {
        return FALSE;
    }
    
    /* For a full validation, we'd need to call the debug_token endpoint
     * This is a synchronous check, so we just do basic validation here */
    return TRUE;
}

void meta_auth_validate_token_async(MetaAccount *account,
                                     MetaAuthCallback callback,
                                     gpointer user_data)
{
    PurpleHttpRequest *request;
    gchar *url;
    
    if (!account->access_token) {
        if (callback) {
            callback(account, FALSE, "No access token", user_data);
        }
        return;
    }
    
    /* Build debug_token URL */
    url = g_strdup_printf("%s?input_token=%s&access_token=%s",
                          META_OAUTH_DEBUG_TOKEN_URL,
                          account->access_token,
                          account->access_token);
    
    request = purple_http_request_new(url);
    purple_http_request_set_method(request, "GET");
    
    MetaValidateData *data = g_new0(MetaValidateData, 1);
    data->account = account;
    data->callback = callback;
    data->user_data = user_data;
    
    purple_http_request(account->pc, request, meta_auth_validate_response_cb, data);
    
    purple_http_request_unref(request);
    g_free(url);
}

typedef struct {
    MetaAccount *account;
    MetaAuthCallback callback;
    gpointer user_data;
} MetaValidateData;

static void meta_auth_validate_response_cb(PurpleHttpConnection *connection,
                                            PurpleHttpResponse *response,
                                            gpointer user_data)
{
    MetaValidateData *data = user_data;
    JsonParser *parser;
    JsonObject *root, *token_data;
    const gchar *response_data;
    gsize response_len;
    gboolean is_valid = FALSE;
    GError *error = NULL;
    
    if (!purple_http_response_is_successful(response)) {
        if (data->callback) {
            data->callback(data->account, FALSE, "Token validation request failed",
                          data->user_data);
        }
        g_free(data);
        return;
    }
    
    response_data = purple_http_response_get_data(response, &response_len);
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, response_data, response_len, &error)) {
        if (data->callback) {
            data->callback(data->account, FALSE, "Failed to parse validation response",
                          data->user_data);
        }
        g_error_free(error);
        g_object_unref(parser);
        g_free(data);
        return;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    
    if (json_object_has_member(root, "data")) {
        token_data = json_object_get_object_member(root, "data");
        is_valid = json_object_get_boolean_member_with_default(token_data, "is_valid", FALSE);
        
        /* Update expiry if available */
        if (json_object_has_member(token_data, "expires_at")) {
            data->account->token_expiry = json_object_get_int_member(token_data, "expires_at");
        }
        
        /* Store user_id if available */
        if (json_object_has_member(token_data, "user_id")) {
            g_free(data->account->user_id);
            data->account->user_id = g_strdup(
                json_object_get_string_member(token_data, "user_id"));
        }
    }
    
    if (data->callback) {
        data->callback(data->account, is_valid, 
                      is_valid ? NULL : "Token is invalid or expired",
                      data->user_data);
    }
    
    g_object_unref(parser);
    g_free(data);
}

void meta_auth_refresh_token(MetaAccount *account,
                              MetaTokenCallback callback,
                              gpointer user_data)
{
    /* Facebook long-lived tokens don't have a refresh token
     * We need to exchange for a new long-lived token before expiry */
    PurpleHttpRequest *request;
    gchar *url;
    
    url = g_strdup_printf("%s/oauth/access_token"
                          "?grant_type=fb_exchange_token"
                          "&client_id=%s"
                          "&fb_exchange_token=%s",
                          META_GRAPH_API_BASE,
                          META_OAUTH_CLIENT_ID,
                          account->access_token);
    
    request = purple_http_request_new(url);
    purple_http_request_set_method(request, "GET");
    
    MetaTokenExchangeData *data = g_new0(MetaTokenExchangeData, 1);
    data->account = account;
    data->callback = callback;
    data->user_data = user_data;
    
    purple_http_request(account->pc, request, meta_auth_token_response_cb, data);
    
    purple_http_request_unref(request);
    g_free(url);
}

void meta_auth_store_token(MetaAccount *account, MetaOAuthToken *token)
{
    if (!account || !token) return;
    
    purple_account_set_string(account->pa, "access_token", token->access_token);
    purple_account_set_int(account->pa, "token_expiry", (int)token->expires_at);
    
    if (token->user_id) {
        purple_account_set_string(account->pa, "user_id", token->user_id);
    }
    
    if (token->page_access_token) {
        purple_account_set_string(account->pa, "page_access_token", 
                                  token->page_access_token);
    }
    
    meta_debug("Token stored successfully (expires: %ld)", token->expires_at);
}

MetaOAuthToken *meta_auth_load_token(MetaAccount *account)
{
    const char *access_token;
    MetaOAuthToken *token;
    
    if (!account) return NULL;
    
    access_token = purple_account_get_string(account->pa, "access_token", NULL);
    if (!access_token || strlen(access_token) == 0) {
        return NULL;
    }
    
    token = g_new0(MetaOAuthToken, 1);
    token->access_token = g_strdup(access_token);
    token->expires_at = purple_account_get_int(account->pa, "token_expiry", 0);
    token->user_id = g_strdup(purple_account_get_string(account->pa, "user_id", NULL));
    token->page_access_token = g_strdup(
        purple_account_get_string(account->pa, "page_access_token", NULL));
    
    return token;
}

void meta_auth_clear_tokens(MetaAccount *account)
{
    if (!account) return;
    
    purple_account_set_string(account->pa, "access_token", NULL);
    purple_account_set_int(account->pa, "token_expiry", 0);
    purple_account_set_string(account->pa, "user_id", NULL);
    purple_account_set_string(account->pa, "page_access_token", NULL);
    purple_account_set_string(account->pa, "session_cookies", NULL);
    
    g_free(account->access_token);
    g_free(account->user_id);
    account->access_token = NULL;
    account->user_id = NULL;
    account->token_expiry = 0;
    
    meta_debug("Tokens cleared");
}

gboolean meta_auth_token_needs_refresh(MetaOAuthToken *token)
{
    if (!token) return TRUE;
    if (token->expires_at <= 0) return FALSE;  /* No expiry set */
    
    gint64 now = time(NULL);
    gint64 refresh_threshold = token->expires_at - META_TOKEN_REFRESH_BUFFER;
    
    return now >= refresh_threshold;
}

gint64 meta_auth_token_expires_in(MetaOAuthToken *token)
{
    if (!token || token->expires_at <= 0) return -1;
    
    gint64 now = time(NULL);
    gint64 expires_in = token->expires_at - now;
    
    return expires_in > 0 ? expires_in : -1;
}

/* ============================================================
 * Cookie-Based Authentication
 * ============================================================ */

MetaSessionCookies *meta_auth_parse_cookies(const char *cookie_string)
{
    MetaSessionCookies *cookies;
    gchar **pairs;
    
    if (!cookie_string) return NULL;
    
    cookies = g_new0(MetaSessionCookies, 1);
    
    pairs = g_strsplit(cookie_string, ";", -1);
    for (int i = 0; pairs[i]; i++) {
        gchar *trimmed = g_strstrip(g_strdup(pairs[i]));
        gchar **kv = g_strsplit(trimmed, "=", 2);
        
        if (kv[0] && kv[1]) {
            if (g_strcmp0(kv[0], "c_user") == 0) {
                cookies->c_user = g_strdup(kv[1]);
            } else if (g_strcmp0(kv[0], "xs") == 0) {
                cookies->xs = g_strdup(kv[1]);
            } else if (g_strcmp0(kv[0], "datr") == 0) {
                cookies->datr = g_strdup(kv[1]);
            } else if (g_strcmp0(kv[0], "fr") == 0) {
                cookies->fr = g_strdup(kv[1]);
            } else if (g_strcmp0(kv[0], "sb") == 0) {
                cookies->sb = g_strdup(kv[1]);
            }
        }
        
        g_strfreev(kv);
        g_free(trimmed);
    }
    g_strfreev(pairs);
    
    return cookies;
}

gboolean meta_auth_validate_cookies(MetaAccount *account,
                                     MetaSessionCookies *cookies)
{
    if (!cookies) return FALSE;
    
    /* Minimum required cookies */
    if (!cookies->c_user || !cookies->xs) {
        return FALSE;
    }
    
    /* Check expiry */
    if (cookies->expires_at > 0 && cookies->expires_at < time(NULL)) {
        return FALSE;
    }
    
    return TRUE;
}

void meta_auth_store_cookies(MetaAccount *account,
                              MetaSessionCookies *cookies)
{
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    
    if (!account || !cookies) return;
    
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    if (cookies->c_user) {
        json_builder_set_member_name(builder, "c_user");
        json_builder_add_string_value(builder, cookies->c_user);
    }
    if (cookies->xs) {
        json_builder_set_member_name(builder, "xs");
        json_builder_add_string_value(builder, cookies->xs);
    }
    if (cookies->datr) {
        json_builder_set_member_name(builder, "datr");
        json_builder_add_string_value(builder, cookies->datr);
    }
    if (cookies->fr) {
        json_builder_set_member_name(builder, "fr");
        json_builder_add_string_value(builder, cookies->fr);
    }
    if (cookies->sb) {
        json_builder_set_member_name(builder, "sb");
        json_builder_add_string_value(builder, cookies->sb);
    }
    
    json_builder_set_member_name(builder, "expires_at");
    json_builder_add_int_value(builder, cookies->expires_at);
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    purple_account_set_string(account->pa, "session_cookies", json_str);
    
    g_free(json_str);
    g_object_unref(gen);
    g_object_unref(builder);
}

MetaSessionCookies *meta_auth_load_cookies(MetaAccount *account)
{
    const char *json_str;
    JsonParser *parser;
    JsonObject *root;
    MetaSessionCookies *cookies;
    GError *error = NULL;
    
    if (!account) return NULL;
    
    json_str = purple_account_get_string(account->pa, "session_cookies", NULL);
    if (!json_str) return NULL;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, json_str, -1, &error)) {
        g_error_free(error);
        g_object_unref(parser);
        return NULL;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    cookies = g_new0(MetaSessionCookies, 1);
    
    cookies->c_user = g_strdup(json_object_get_string_member_with_default(root, "c_user", NULL));
    cookies->xs = g_strdup(json_object_get_string_member_with_default(root, "xs", NULL));
    cookies->datr = g_strdup(json_object_get_string_member_with_default(root, "datr", NULL));
    cookies->fr = g_strdup(json_object_get_string_member_with_default(root, "fr", NULL));
    cookies->sb = g_strdup(json_object_get_string_member_with_default(root, "sb", NULL));
    cookies->expires_at = json_object_get_int_member_with_default(root, "expires_at", 0);
    
    g_object_unref(parser);
    
    return cookies;
}

gchar *meta_auth_cookies_to_header(MetaSessionCookies *cookies)
{
    GString *header;
    
    if (!cookies) return NULL;
    
    header = g_string_new(NULL);
    
    if (cookies->c_user) {
        g_string_append_printf(header, "c_user=%s; ", cookies->c_user);
    }
    if (cookies->xs) {
        g_string_append_printf(header, "xs=%s; ", cookies->xs);
    }
    if (cookies->datr) {
        g_string_append_printf(header, "datr=%s; ", cookies->datr);
    }
    if (cookies->fr) {
        g_string_append_printf(header, "fr=%s; ", cookies->fr);
    }
    if (cookies->sb) {
        g_string_append_printf(header, "sb=%s; ", cookies->sb);
    }
    
    /* Remove trailing "; " */
    if (header->len > 2) {
        g_string_truncate(header, header->len - 2);
    }
    
    return g_string_free(header, FALSE);
}

/* ============================================================
 * Memory Management
 * ============================================================ */

void meta_oauth_token_free(MetaOAuthToken *token)
{
    if (!token) return;
    
    g_free(token->access_token);
    g_free(token->token_type);
    g_free(token->refresh_token);
    g_free(token->user_id);
    g_free(token->page_id);
    g_free(token->page_access_token);
    g_list_free_full(token->scopes, g_free);
    g_free(token);
}

void meta_session_cookies_free(MetaSessionCookies *cookies)
{
    if (!cookies) return;
    
    g_free(cookies->c_user);
    g_free(cookies->xs);
    g_free(cookies->datr);
    g_free(cookies->fr);
    g_free(cookies->sb);
    g_free(cookies);
}

void meta_auth_state_free(MetaAuthState *state)
{
    if (!state) return;
    
    g_free(state->state);
    g_free(state->code_verifier);
    g_free(state->code_challenge);
    
    if (state->timeout_handle) {
        g_source_remove(state->timeout_handle);
    }
    
    if (state->http_server) {
        g_object_unref(state->http_server);
    }
    
    g_free(state);
}

MetaOAuthToken *meta_oauth_token_copy(MetaOAuthToken *token)
{
    MetaOAuthToken *copy;
    
    if (!token) return NULL;
    
    copy = g_new0(MetaOAuthToken, 1);
    copy->access_token = g_strdup(token->access_token);
    copy->token_type = g_strdup(token->token_type);
    copy->expires_at = token->expires_at;
    copy->refresh_token = g_strdup(token->refresh_token);
    copy->user_id = g_strdup(token->user_id);
    copy->page_id = g_strdup(token->page_id);
    copy->page_access_token = g_strdup(token->page_access_token);
    
    /* Copy scopes list */
    for (GList *l = token->scopes; l; l = l->next) {
        copy->scopes = g_list_append(copy->scopes, g_strdup(l->data));
    }
    
    return copy;
}