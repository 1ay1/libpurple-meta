/**
 * instagram.c
 * 
 * Instagram DM service module implementation for libpurple-meta
 * Handles Instagram-specific API calls and Direct Message handling
 * 
 * Note: Instagram's private API changes frequently. If something breaks,
 * check if the app version or endpoints need updating in meta-config.json
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#include "instagram.h"
#include "../common/meta-http.h"
#include "../common/meta-auth.h"
#include "../common/meta-config.h"
#include "../common/meta-security.h"
#include "../common/meta-websocket.h"
#include <json-glib/json-glib.h>
#include <string.h>
#include <time.h>

/* Include compatibility layer */
#include "../common/purple-compat.h"

/* ============================================================
 * Forward declarations for async functions and callbacks
 * ============================================================ */

/* Async functions */
static void instagram_fetch_user_info_async(MetaAccount *account);
static void instagram_sync_inbox_async(MetaAccount *account);

/* HTTP callbacks */
static void instagram_user_info_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_inbox_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_send_message_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_typing_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_mark_seen_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_reaction_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_unsend_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_thread_items_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_leave_thread_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_mute_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_approve_cb(MetaHttpResponse *response, gpointer user_data);
static void instagram_decline_cb(MetaHttpResponse *response, gpointer user_data);

/* Rate limiting - Instagram is way more aggressive than Messenger about
 * blocking automated access. Keep these conservative or you'll get soft-banned.
 * These are fallback values; config file overrides them */
#define INSTAGRAM_RATE_LIMIT_CALLS   100
#define INSTAGRAM_RATE_LIMIT_WINDOW  3600  /* 1 hour */

/* App version info - these get outdated every few weeks when IG pushes updates.
 * Grab new values from an APK if requests start failing */
#define INSTAGRAM_APP_VERSION       "275.0.0.27.98"
#define INSTAGRAM_VERSION_CODE      "458229237"
#define INSTAGRAM_SIG_KEY_VERSION   "4"

/* User agent for API requests - fallback default
 * Prefer meta_config_get_ig_user_agent() when available */
#define INSTAGRAM_USER_AGENT \
    "Instagram " INSTAGRAM_APP_VERSION " Android (30/11; 420dpi; 1080x2220; " \
    "samsung; SM-G975F; beyond2; exynos9820; en_US; " INSTAGRAM_VERSION_CODE ")"

/* Helper to get User-Agent from config or fallback */
static const gchar *get_instagram_user_agent(void)
{
    const gchar *ua = meta_config_get_ig_user_agent();
    return (ua && ua[0] != '\0') ? ua : INSTAGRAM_USER_AGENT;
}

/* Helper to get API base URL from config or fallback */
static const gchar * G_GNUC_UNUSED get_instagram_api_base(void)
{
    const gchar *base = meta_config_get_ig_api_base();
    return (base && base[0] != '\0') ? base : INSTAGRAM_API_BASE;
}

/* ============================================================
 * Internal Helpers
 * ============================================================ */

static InstagramData *instagram_get_data(MetaAccount *account)
{
    if (!account || !account->instagram) return NULL;
    return (InstagramData *)account->instagram->priv;
}

static gint64 G_GNUC_UNUSED get_timestamp_ms(void)
{
    return g_get_real_time() / 1000;
}

static gint64 get_timestamp_us(void)
{
    return g_get_real_time();
}

/* ============================================================
 * UUID and Device ID Generation
 * ============================================================ */

gchar *instagram_generate_uuid(void)
{
    return g_uuid_string_random();
}

gchar *instagram_generate_device_id(const char *seed)
{
    GChecksum *checksum;
    gchar *device_id;
    const gchar *digest;
    
    checksum = g_checksum_new(G_CHECKSUM_MD5);
    
    if (seed) {
        g_checksum_update(checksum, (guchar *)seed, strlen(seed));
    } else {
        gchar *random = g_uuid_string_random();
        g_checksum_update(checksum, (guchar *)random, strlen(random));
        g_free(random);
    }
    
    digest = g_checksum_get_string(checksum);
    device_id = g_strdup_printf("android-%s", digest);
    
    g_checksum_free(checksum);
    
    return device_id;
}

/* ============================================================
 * Service Lifecycle
 * ============================================================ */

/* Service callback implementations */
static gboolean service_connect(MetaAccount *account);
static void service_disconnect(MetaAccount *account);
static gboolean service_reconnect(MetaAccount *account);
static gboolean service_send_message(MetaAccount *account, const char *to,
                                      const char *message, MetaMessageType type);
static gboolean service_send_typing(MetaAccount *account, const char *to,
                                     gboolean typing);
static gboolean service_mark_read(MetaAccount *account, const char *thread_id,
                                   const char *message_id);
static GList *service_get_threads(MetaAccount *account);
static MetaThread *service_get_thread(MetaAccount *account, const char *thread_id);
static GList *service_get_thread_messages(MetaAccount *account,
                                           const char *thread_id,
                                           int limit, const char *before_cursor);
static gboolean service_upload_media(MetaAccount *account, const char *thread_id,
                                      const char *filepath, MetaMessageType type);
static gchar *service_download_media(MetaAccount *account, const char *media_url);
static void service_set_presence(MetaAccount *account, PurpleStatusPrimitive status);

MetaService *instagram_service_new(void)
{
    MetaService *service = g_new0(MetaService, 1);
    InstagramData *data = g_new0(InstagramData, 1);
    
    service->id = "instagram";
    service->display_name = "Instagram DMs";
    
    /* Set callbacks */
    service->connect = service_connect;
    service->disconnect = service_disconnect;
    service->reconnect = service_reconnect;
    service->send_message = service_send_message;
    service->send_typing = service_send_typing;
    service->mark_read = service_mark_read;
    service->get_threads = service_get_threads;
    service->get_thread = service_get_thread;
    service->get_thread_messages = service_get_thread_messages;
    service->upload_media = service_upload_media;
    service->download_media = service_download_media;
    service->set_presence = service_set_presence;
    
    /* Initialize data */
    data->pending_threads = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, NULL);
    
    /* Generate device identifiers */
    data->uuid = instagram_generate_uuid();
    data->phone_id = instagram_generate_uuid();
    data->advertising_id = instagram_generate_uuid();
    
    service->priv = data;
    
    return service;
}

void instagram_service_free(MetaService *service)
{
    if (!service) return;
    
    InstagramData *data = (InstagramData *)service->priv;
    if (data) {
        g_free(data->session_id);
        g_free(data->csrf_token);
        g_free(data->device_id);
        g_free(data->uuid);
        g_free(data->phone_id);
        g_free(data->advertising_id);
        g_free(data->user_id);
        g_free(data->username);
        g_free(data->full_name);
        g_free(data->profile_pic_url);
        g_free(data->seq_id);
        g_free(data->snapshot_at_ms);
        g_free(data->cursor);
        g_free(data->mqtt_client_id);
        
        if (data->pending_threads) {
            g_hash_table_destroy(data->pending_threads);
        }
        
        g_free(data);
    }
    
    g_free(service);
}

gboolean instagram_init(MetaAccount *account)
{
    InstagramData *data;
    const char *username;
    
    if (!account || !account->instagram) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    /* Generate device ID based on username */
    username = purple_account_get_username(account->pa);
    if (username) {
        g_free(data->device_id);
        data->device_id = instagram_generate_device_id(username);
    }
    
    meta_debug("Instagram service initialized");
    return TRUE;
}

void instagram_cleanup(MetaAccount *account)
{
    if (!account) return;
    
    meta_debug("Instagram service cleaned up");
}

/* ============================================================
 * API Headers and Request Signing
 * ============================================================ */

GHashTable *instagram_get_headers(InstagramData *data)
{
    GHashTable *headers;
    MetaConfig *config;
    const gchar *user_agent;
    
    /* Try to get headers from config first */
    headers = meta_config_get_ig_headers();
    if (!headers) {
        /* Fallback: create headers manually */
        headers = g_hash_table_new_full(g_str_hash, g_str_equal,
                                         g_free, g_free);
    }
    
    /* Get config for values */
    config = meta_config_get();
    
    /* User-Agent from config or fallback */
    user_agent = get_instagram_user_agent();
    g_hash_table_insert(headers, g_strdup("User-Agent"), 
                        g_strdup(user_agent));
    
    g_hash_table_insert(headers, g_strdup("Content-Type"),
                        g_strdup("application/x-www-form-urlencoded; charset=UTF-8"));
    g_hash_table_insert(headers, g_strdup("Accept-Language"),
                        g_strdup("en-US"));
    
    /* Use config values for Instagram headers if available */
    if (config && config->instagram.x_ig_capabilities) {
        g_hash_table_insert(headers, g_strdup("X-IG-Capabilities"),
                            g_strdup(config->instagram.x_ig_capabilities));
    } else {
        g_hash_table_insert(headers, g_strdup("X-IG-Capabilities"),
                            g_strdup("3brTvwE="));
    }
    
    if (config && config->instagram.x_ig_connection_type) {
        g_hash_table_insert(headers, g_strdup("X-IG-Connection-Type"),
                            g_strdup(config->instagram.x_ig_connection_type));
    } else {
        g_hash_table_insert(headers, g_strdup("X-IG-Connection-Type"),
                            g_strdup("WIFI"));
    }
    
    if (config && config->instagram.x_ig_app_id) {
        g_hash_table_insert(headers, g_strdup("X-IG-App-ID"),
                            g_strdup(config->instagram.x_ig_app_id));
    } else {
        g_hash_table_insert(headers, g_strdup("X-IG-App-ID"),
                            g_strdup("567067343352427"));
    }
    
    /* Add session-specific headers from InstagramData */
    if (data) {
        if (data->csrf_token) {
            g_hash_table_insert(headers, g_strdup("X-CSRFToken"),
                                g_strdup(data->csrf_token));
        }
        if (data->device_id) {
            g_hash_table_insert(headers, g_strdup("X-IG-Device-ID"),
                                g_strdup(data->device_id));
        }
        if (data->uuid) {
            g_hash_table_insert(headers, g_strdup("X-IG-Android-ID"),
                                g_strdup(data->uuid));
        }
    }
    
    return headers;
}

gchar *instagram_get_device_info(InstagramData *data)
{
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "manufacturer");
    json_builder_add_string_value(builder, "samsung");
    
    json_builder_set_member_name(builder, "model");
    json_builder_add_string_value(builder, "SM-G975F");
    
    json_builder_set_member_name(builder, "android_version");
    json_builder_add_int_value(builder, 30);
    
    json_builder_set_member_name(builder, "android_release");
    json_builder_add_string_value(builder, "11");
    
    if (data && data->device_id) {
        json_builder_set_member_name(builder, "device_id");
        json_builder_add_string_value(builder, data->device_id);
    }
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    g_object_unref(gen);
    g_object_unref(builder);
    
    return json_str;
}

gchar *instagram_sign_request(const char *payload)
{
    /* Instagram uses a signature for some requests
     * The signature key changes with app versions
     * For now, we'll use the unsigned format which works for most endpoints */
    
    gchar *encoded = g_uri_escape_string(payload, NULL, TRUE);
    gchar *signed_body = g_strdup_printf("signed_body=SIGNATURE.%s", encoded);
    
    g_free(encoded);
    
    return signed_body;
}

/* ============================================================
 * Rate Limiting
 * ============================================================ */

gboolean instagram_is_rate_limited(InstagramData *data)
{
    guint rate_limit_calls;
    guint rate_limit_window;
    gint64 now;
    gint64 window_start;
    
    if (!data) return FALSE;
    
    /* Get rate limits from config */
    rate_limit_calls = meta_config_get_rate_limit_calls(TRUE);  /* TRUE = Instagram */
    rate_limit_window = meta_config_get_rate_limit_window(TRUE);
    
    /* Use defaults if config not available */
    if (rate_limit_calls == 0) rate_limit_calls = INSTAGRAM_RATE_LIMIT_CALLS;
    if (rate_limit_window == 0) rate_limit_window = INSTAGRAM_RATE_LIMIT_WINDOW;
    
    now = time(NULL);
    window_start = now - rate_limit_window;
    
    /* Reset counter if window has passed */
    if (data->last_api_call < window_start) {
        data->api_call_count = 0;
        return FALSE;
    }
    
    /* Check if we've exceeded the limit */
    return (data->api_call_count >= rate_limit_calls);
}

void instagram_record_api_call(InstagramData *data)
{
    guint rate_limit_window;
    gint64 now;
    gint64 window_start;
    
    if (!data) return;
    
    rate_limit_window = meta_config_get_rate_limit_window(TRUE);
    if (rate_limit_window == 0) rate_limit_window = INSTAGRAM_RATE_LIMIT_WINDOW;
    
    now = time(NULL);
    window_start = now - rate_limit_window;
    
    /* Reset counter if window has passed */
    if (data->last_api_call < window_start) {
        data->api_call_count = 0;
    }
    
    data->last_api_call = now;
    data->api_call_count++;
}

/* ============================================================
 * Connection
 * ============================================================ */

static gboolean service_connect(MetaAccount *account)
{
    return instagram_connect(account);
}

gboolean instagram_connect(MetaAccount *account)
{
    InstagramData *data;
    
    if (!account) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) {
        instagram_init(account);
        data = instagram_get_data(account);
    }
    
    meta_debug("Connecting to Instagram...");
    
    /* Fetch user info and inbox */
    instagram_fetch_user_info_async(account);
    instagram_sync_inbox_async(account);
    
    return TRUE;
}

static void service_disconnect(MetaAccount *account)
{
    instagram_disconnect(account);
}

void instagram_disconnect(MetaAccount *account)
{
    if (!account) return;
    
    meta_debug("Disconnecting from Instagram...");
    
    instagram_cleanup(account);
}

static gboolean service_reconnect(MetaAccount *account)
{
    return instagram_reconnect(account);
}

gboolean instagram_reconnect(MetaAccount *account)
{
    instagram_disconnect(account);
    return instagram_connect(account);
}

/* ============================================================
 * User Info
 * ============================================================ */

static void instagram_fetch_user_info_async(MetaAccount *account)
{
    InstagramData *data;
    MetaHttpRequest *request;
    gchar *url;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    
    data = instagram_get_data(account);
    if (!data) return;
    
    url = g_strdup_printf("%s/accounts/current_user/?edit=true", INSTAGRAM_API_BASE);
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "GET");
    
    /* Set headers */
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_user_info_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
}

static void instagram_user_info_cb(MetaHttpResponse *response, gpointer user_data)
{
    MetaAccount *account = user_data;
    InstagramData *data;
    const gchar *response_data;
    gsize response_len;
    JsonParser *parser;
    JsonObject *root, *user;
    
    if (!meta_http_response_is_successful(response)) {
        meta_warning("Failed to fetch Instagram user info");
        return;
    }
    
    data = instagram_get_data(account);
    if (!data) return;
    
    response_data = meta_http_response_get_data(response, &response_len);
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, response_data, response_len, NULL)) {
        g_object_unref(parser);
        return;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    
    if (json_object_has_member(root, "user")) {
        user = json_object_get_object_member(root, "user");
        
        g_free(data->user_id);
        data->user_id = g_strdup(json_object_get_string_member(user, "pk"));
        
        g_free(data->username);
        data->username = g_strdup(json_object_get_string_member(user, "username"));
        
        g_free(data->full_name);
        data->full_name = g_strdup(
            json_object_get_string_member_with_default(user, "full_name", data->username));
        
        g_free(data->profile_pic_url);
        data->profile_pic_url = g_strdup(
            json_object_get_string_member_with_default(user, "profile_pic_url", NULL));
        
        /* Update account user_id */
        g_free(account->user_id);
        account->user_id = g_strdup(data->user_id);
        
        meta_debug("Instagram user info: %s (%s)", data->username, data->user_id);
    }
    
    g_object_unref(parser);
}

/* ============================================================
 * Inbox Sync
 * ============================================================ */

static void instagram_sync_inbox_async(MetaAccount *account)
{
    InstagramData *data;
    MetaHttpRequest *request;
    gchar *url;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    
    data = instagram_get_data(account);
    if (!data) return;
    
    meta_debug("Syncing Instagram inbox...");
    
    if (data->cursor) {
        url = g_strdup_printf("%s?cursor=%s&direction=older",
                              INSTAGRAM_INBOX_API, data->cursor);
    } else {
        url = g_strdup(INSTAGRAM_INBOX_API);
    }
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "GET");
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_inbox_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    
    instagram_record_api_call(data);
}

static void instagram_inbox_cb(MetaHttpResponse *response, gpointer user_data)
{
    MetaAccount *account = user_data;
    InstagramData *data;
    const gchar *response_data;
    gsize response_len;
    GList *threads G_GNUC_UNUSED;
    JsonParser *parser;
    JsonObject *root, *inbox;
    
    if (!meta_http_response_is_successful(response)) {
        meta_error("Failed to fetch Instagram inbox");
        return;
    }
    
    data = instagram_get_data(account);
    if (!data) return;
    
    response_data = meta_http_response_get_data(response, &response_len);
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, response_data, response_len, NULL)) {
        g_object_unref(parser);
        return;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    
    /* Update sync state */
    if (json_object_has_member(root, "seq_id")) {
        g_free(data->seq_id);
        data->seq_id = g_strdup_printf("%lld", 
            (long long)json_object_get_int_member(root, "seq_id"));
    }
    
    if (json_object_has_member(root, "snapshot_at_ms")) {
        g_free(data->snapshot_at_ms);
        data->snapshot_at_ms = g_strdup_printf("%lld",
            (long long)json_object_get_int_member(root, "snapshot_at_ms"));
    }
    
    /* Parse inbox */
    if (json_object_has_member(root, "inbox")) {
        inbox = json_object_get_object_member(root, "inbox");
        
        if (json_object_has_member(inbox, "threads")) {
            JsonArray *threads_array = json_object_get_array_member(inbox, "threads");
            guint count = json_array_get_length(threads_array);
            
            for (guint i = 0; i < count; i++) {
                JsonObject *thread_obj = json_array_get_object_element(threads_array, i);
                MetaThread *thread = instagram_parse_thread(thread_obj);
                
                if (thread) {
                    g_hash_table_insert(account->threads, g_strdup(thread->id), thread);
                    
                    /* Create buddy for 1:1 threads */
                    if (!thread->is_group && thread->participants) {
                        MetaUser *user = thread->participants->data;
                        PurpleBuddy *buddy = purple_blist_find_buddy(account->pa, user->id);
                        if (!buddy) {
                            buddy = purple_buddy_new(account->pa, user->id, 
                                                     user->display_name);
                            purple_blist_add_buddy(buddy, NULL, NULL, NULL);
                        }
                    }
                }
            }
            
            meta_debug("Synced %u Instagram threads", count);
        }
        
        /* Check for pagination */
        if (json_object_has_member(inbox, "oldest_cursor")) {
            g_free(data->cursor);
            data->cursor = g_strdup(json_object_get_string_member(inbox, "oldest_cursor"));
        }
    }
    
    data->last_sync = time(NULL);
    
    g_object_unref(parser);
}

/* ============================================================
 * Messaging
 * ============================================================ */

static gboolean service_send_message(MetaAccount *account, const char *to,
                                      const char *message, MetaMessageType type)
{
    return instagram_send_message(account, to, message, type);
}

gboolean instagram_send_message(MetaAccount *account, const char *to,
                                 const char *message, MetaMessageType type)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str, *post_data, *url;
    gchar *client_context;
    gchar *sanitized_message = NULL;
    
    if (!account || !to || !message) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    /* Validate thread ID to prevent injection */
    if (!meta_security_validate_thread_id(to)) {
        meta_warning("Invalid thread ID format: %s", 
                     meta_security_sanitize_for_log(to));
        return FALSE;
    }
    
    /* Validate and sanitize message */
    if (!meta_security_validate_message(message, &sanitized_message)) {
        meta_warning("Message validation failed");
        return FALSE;
    }
    
    /* Check rate limiting from config */
    if (instagram_is_rate_limited(data)) {
        meta_warning("Instagram rate limited");
        g_free(sanitized_message);
        return FALSE;
    }
    
    /* Use sanitized log output */
    meta_security_debug("Sending Instagram message to %s", to);
    
    /* Generate client context (unique ID for this message) */
    client_context = g_strdup_printf("%lld", (long long)get_timestamp_us());
    
    /* Build request JSON */
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "action");
    json_builder_add_string_value(builder, "send_item");
    
    json_builder_set_member_name(builder, "thread_ids");
    json_builder_begin_array(builder);
    json_builder_add_string_value(builder, to);
    json_builder_end_array(builder);
    
    json_builder_set_member_name(builder, "client_context");
    json_builder_add_string_value(builder, client_context);
    
    json_builder_set_member_name(builder, "text");
    json_builder_add_string_value(builder, sanitized_message ? sanitized_message : message);
    
    if (data->device_id) {
        json_builder_set_member_name(builder, "device_id");
        json_builder_add_string_value(builder, data->device_id);
    }
    
    if (data->uuid) {
        json_builder_set_member_name(builder, "_uuid");
        json_builder_add_string_value(builder, data->uuid);
    }
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    /* Sign the request */
    post_data = instagram_sign_request(json_str);
    
    /* Clean up sanitized message */
    g_free(sanitized_message);
    
    /* Build URL using config */
    url = g_strdup(INSTAGRAM_SEND_API);
    
    /* Create request */
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_send_message_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    g_free(json_str);
    g_free(client_context);
    g_object_unref(gen);
    g_object_unref(builder);
    
    instagram_record_api_call(data);
    
    return TRUE;
}

static void instagram_send_message_cb(MetaHttpResponse *response,
                                       
                                       gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        int code = meta_http_response_get_code(response);
        meta_error("Failed to send Instagram message: %d", code);
        return;
    }
    
    meta_debug("Instagram message sent successfully");
}

static gboolean service_send_typing(MetaAccount *account, const char *to,
                                     gboolean typing)
{
    return instagram_send_typing(account, to, typing);
}

gboolean instagram_send_typing(MetaAccount *account, const char *thread_id,
                                gboolean typing)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url, *post_data;
    
    if (!account || !thread_id) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("Sending Instagram typing to %s: %s", thread_id, typing ? "on" : "off");
    
    url = g_strdup_printf("%s/%s/activity/", INSTAGRAM_THREADS_API, thread_id);
    
    post_data = g_strdup_printf("activity_status=%d&_uuid=%s",
                                typing ? 1 : 0,
                                data->uuid ? data->uuid : "");
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_typing_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    
    return TRUE;
}

static void instagram_typing_cb(MetaHttpResponse *response,
                                 
                                 gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        meta_debug("Failed to send Instagram typing indicator");
    }
}

static gboolean service_mark_read(MetaAccount *account, const char *thread_id,
                                   const char *message_id)
{
    return instagram_mark_seen(account, thread_id, message_id);
}

gboolean instagram_mark_seen(MetaAccount *account, const char *thread_id,
                              const char *item_id)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url, *post_data;
    
    if (!account || !thread_id) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("Marking Instagram thread %s as seen", thread_id);
    
    url = g_strdup_printf("%s/%s/items/%s/seen/", 
                          INSTAGRAM_THREADS_API, thread_id,
                          item_id ? item_id : "");
    
    post_data = g_strdup_printf("_uuid=%s&use_unified_inbox=true",
                                data->uuid ? data->uuid : "");
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_mark_seen_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    
    instagram_record_api_call(data);
    
    return TRUE;
}

static void instagram_mark_seen_cb(MetaHttpResponse *response,
                                    
                                    gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        meta_debug("Failed to mark Instagram thread as seen");
    }
}

gboolean instagram_send_like(MetaAccount *account, const char *thread_id,
                              const char *item_id)
{
    return instagram_send_reaction(account, thread_id, item_id, "❤️");
}

gboolean instagram_send_reaction(MetaAccount *account, const char *thread_id,
                                  const char *item_id, const char *emoji)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url, *post_data;
    gchar *client_context;
    
    if (!account || !thread_id || !item_id) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("Sending reaction %s to item %s", emoji, item_id);
    
    client_context = g_strdup_printf("%lld", (long long)get_timestamp_us());
    
    url = g_strdup_printf("%s/broadcast/react/", INSTAGRAM_DIRECT_API);
    
    gchar *encoded_emoji = g_uri_escape_string(emoji, NULL, TRUE);
    post_data = g_strdup_printf(
        "thread_ids=[%s]&item_id=%s&reaction_type=like&reaction_status=created"
        "&emoji=%s&client_context=%s&_uuid=%s",
        thread_id, item_id, encoded_emoji, client_context,
        data->uuid ? data->uuid : "");
    g_free(encoded_emoji);
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_reaction_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    g_free(client_context);
    
    instagram_record_api_call(data);
    
    return TRUE;
}

static void instagram_reaction_cb(MetaHttpResponse *response,
                                   
                                   gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        meta_debug("Failed to send Instagram reaction");
    }
}

gboolean instagram_unsend_message(MetaAccount *account, const char *thread_id,
                                   const char *item_id)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url, *post_data;
    
    if (!account || !thread_id || !item_id) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("Unsending Instagram message %s", item_id);
    
    url = g_strdup_printf("%s/%s/items/%s/delete/",
                          INSTAGRAM_THREADS_API, thread_id, item_id);
    
    post_data = g_strdup_printf("_uuid=%s", data->uuid ? data->uuid : "");
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_unsend_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    
    instagram_record_api_call(data);
    
    return TRUE;
}

static void instagram_unsend_cb(MetaHttpResponse *response,
                                 
                                 gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        meta_debug("Failed to unsend Instagram message");
    }
}

/* ============================================================
 * Media
 * ============================================================ */

static gboolean service_upload_media(MetaAccount *account, const char *thread_id,
                                      const char *filepath, MetaMessageType type)
{
    if (type == META_MSG_IMAGE) {
        return instagram_send_photo(account, thread_id, filepath);
    } else if (type == META_MSG_AUDIO) {
        return instagram_send_voice(account, thread_id, filepath);
    }
    return FALSE;
}

gboolean instagram_send_photo(MetaAccount *account, const char *thread_id,
                               const char *filepath)
{
    meta_debug("Sending photo to thread %s: %s", thread_id, filepath);
    /* Photo upload requires:
     * 1. Upload to rupload endpoint
     * 2. Configure the upload
     * 3. Send to thread
     * This is a simplified placeholder */
    return FALSE;  /* TODO: Implement */
}

gboolean instagram_send_voice(MetaAccount *account, const char *thread_id,
                               const char *filepath)
{
    meta_debug("Sending voice to thread %s: %s", thread_id, filepath);
    return FALSE;  /* TODO: Implement */
}

gboolean instagram_send_link(MetaAccount *account, const char *thread_id,
                              const char *url, const char *text)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *api_url, *post_data;
    gchar *client_context;
    
    if (!account || !thread_id || !url) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("Sending link to thread %s: %s", thread_id, url);
    
    client_context = g_strdup_printf("%lld", (long long)get_timestamp_us());
    
    api_url = g_strdup_printf("%s/broadcast/link/", INSTAGRAM_DIRECT_API);
    
    gchar *encoded_url = g_uri_escape_string(url, NULL, TRUE);
    gchar *encoded_text = text ? g_uri_escape_string(text, NULL, TRUE) : g_strdup("");
    
    post_data = g_strdup_printf(
        "thread_ids=[%s]&link_urls=[%s]&link_text=%s&client_context=%s&_uuid=%s",
        thread_id, encoded_url, encoded_text, client_context,
        data->uuid ? data->uuid : "");
    
    g_free(encoded_url);
    g_free(encoded_text);
    
    request = meta_http_request_new(api_url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_send_message_cb, account);
    
    meta_http_request_free(request);
    g_free(api_url);
    g_free(post_data);
    g_free(client_context);
    
    instagram_record_api_call(data);
    
    return TRUE;
}

gboolean instagram_share_post(MetaAccount *account, const char *thread_id,
                               const char *media_id)
{
    meta_debug("Sharing post %s to thread %s", media_id, thread_id);
    return FALSE;  /* TODO: Implement */
}

static gchar *service_download_media(MetaAccount *account, const char *media_url)
{
    return instagram_download_media(account, media_url);
}

gchar *instagram_download_media(MetaAccount *account, const char *media_url)
{
    /* For now, just return the URL */
    meta_debug("Download requested for: %s", media_url);
    return g_strdup(media_url);
}

/* ============================================================
 * Thread Management
 * ============================================================ */

static GList *service_get_threads(MetaAccount *account)
{
    return instagram_get_inbox(account);
}

GList *instagram_get_inbox(MetaAccount *account)
{
    if (!account) return NULL;
    
    /* Trigger async fetch */
    instagram_sync_inbox_async(account);
    
    /* Return cached threads */
    GList *threads = NULL;
    GHashTableIter iter;
    gpointer key, value;
    
    g_hash_table_iter_init(&iter, account->threads);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        threads = g_list_append(threads, value);
    }
    
    return threads;
}

GList *instagram_get_pending_inbox(MetaAccount *account)
{
    InstagramData *data;
    
    if (!account) return NULL;
    
    data = instagram_get_data(account);
    if (!data || !data->pending_threads) return NULL;
    
    GList *threads = NULL;
    GHashTableIter iter;
    gpointer key, value;
    
    g_hash_table_iter_init(&iter, data->pending_threads);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        threads = g_list_append(threads, value);
    }
    
    return threads;
}

static MetaThread *service_get_thread(MetaAccount *account, const char *thread_id)
{
    return instagram_get_thread(account, thread_id);
}

MetaThread *instagram_get_thread(MetaAccount *account, const char *thread_id)
{
    if (!account || !thread_id) return NULL;
    
    return g_hash_table_lookup(account->threads, thread_id);
}

static GList *service_get_thread_messages(MetaAccount *account,
                                           const char *thread_id,
                                           int limit, const char *before_cursor)
{
    return instagram_get_thread_items(account, thread_id, before_cursor);
}

GList *instagram_get_thread_items(MetaAccount *account, const char *thread_id,
                                   const char *cursor)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url;
    
    if (!account || !thread_id) return NULL;
    
    data = instagram_get_data(account);
    if (!data) return NULL;
    
    meta_debug("Fetching items for thread %s", thread_id);
    
    if (cursor) {
        url = g_strdup_printf("%s/%s/?cursor=%s",
                              INSTAGRAM_THREADS_API, thread_id, cursor);
    } else {
        url = g_strdup_printf("%s/%s/", INSTAGRAM_THREADS_API, thread_id);
    }
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "GET");
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_thread_items_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    
    instagram_record_api_call(data);
    
    return NULL;  /* Async */
}

static void instagram_thread_items_cb(MetaHttpResponse *response,
                                       
                                       gpointer user_data)
{
    const gchar *response_data;
    gsize response_len;
    GList *messages;
    
    if (!meta_http_response_is_successful(response)) {
        meta_error("Failed to fetch Instagram thread items");
        return;
    }
    
    response_data = meta_http_response_get_data(response, &response_len);
    messages = instagram_parse_thread_items(response_data);
    
    /* Messages would be delivered to conversation */
    g_list_free_full(messages, g_free);  /* TODO: proper free */
}

gchar *instagram_create_thread(MetaAccount *account, GList *user_ids)
{
    meta_debug("Creating Instagram thread");
    return NULL;  /* TODO: Implement */
}

gchar *instagram_create_group(MetaAccount *account, GList *user_ids,
                               const char *title)
{
    meta_debug("Creating Instagram group: %s", title);
    return NULL;  /* TODO: Implement */
}

gboolean instagram_leave_thread(MetaAccount *account, const char *thread_id)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url, *post_data;
    
    if (!account || !thread_id) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("Leaving Instagram thread %s", thread_id);
    
    url = g_strdup_printf("%s/%s/leave/", INSTAGRAM_THREADS_API, thread_id);
    post_data = g_strdup_printf("_uuid=%s", data->uuid ? data->uuid : "");
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_leave_thread_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    
    instagram_record_api_call(data);
    
    return TRUE;
}

static void instagram_leave_thread_cb(MetaHttpResponse *response,
                                       
                                       gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        meta_debug("Failed to leave Instagram thread");
    }
}

gboolean instagram_add_users_to_thread(MetaAccount *account,
                                        const char *thread_id,
                                        GList *user_ids)
{
    meta_debug("Adding users to Instagram thread %s", thread_id);
    return FALSE;  /* TODO: Implement */
}

gboolean instagram_mute_thread(MetaAccount *account, const char *thread_id,
                                gboolean mute)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url, *post_data;
    
    if (!account || !thread_id) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("%s Instagram thread %s", mute ? "Muting" : "Unmuting", thread_id);
    
    url = g_strdup_printf("%s/%s/%s/",
                          INSTAGRAM_THREADS_API, thread_id,
                          mute ? "mute" : "unmute");
    post_data = g_strdup_printf("_uuid=%s", data->uuid ? data->uuid : "");
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_mute_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    
    return TRUE;
}

static void instagram_mute_cb(MetaHttpResponse *response,
                               
                               gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        meta_debug("Failed to mute/unmute Instagram thread");
    }
}

gboolean instagram_approve_thread(MetaAccount *account, const char *thread_id)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url, *post_data;
    
    if (!account || !thread_id) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("Approving Instagram thread %s", thread_id);
    
    url = g_strdup_printf("%s/%s/approve/", INSTAGRAM_THREADS_API, thread_id);
    post_data = g_strdup_printf("_uuid=%s", data->uuid ? data->uuid : "");
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_approve_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    
    instagram_record_api_call(data);
    
    return TRUE;
}

static void instagram_approve_cb(MetaHttpResponse *response,
                                  
                                  gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        meta_debug("Failed to approve Instagram thread");
    }
}

gboolean instagram_decline_thread(MetaAccount *account, const char *thread_id)
{
    InstagramData *data;
    MetaHttpRequest *request;
    GHashTable *headers;
    GHashTableIter iter;
    gpointer key, value;
    gchar *url, *post_data;
    
    if (!account || !thread_id) return FALSE;
    
    data = instagram_get_data(account);
    if (!data) return FALSE;
    
    meta_debug("Declining Instagram thread %s", thread_id);
    
    url = g_strdup_printf("%s/%s/decline/", INSTAGRAM_THREADS_API, thread_id);
    post_data = g_strdup_printf("_uuid=%s", data->uuid ? data->uuid : "");
    
    request = meta_http_request_new(url);
    meta_http_request_set_method(request, "POST");
    meta_http_request_set_body(request, post_data, strlen(post_data));
    
    headers = instagram_get_headers(data);
    g_hash_table_iter_init(&iter, headers);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        meta_http_request_set_header(request, key, value);
    }
    g_hash_table_destroy(headers);
    
    meta_http_request_execute(account->pc, request, instagram_decline_cb, account);
    
    meta_http_request_free(request);
    g_free(url);
    g_free(post_data);
    
    instagram_record_api_call(data);
    
    return TRUE;
}

static void instagram_decline_cb(MetaHttpResponse *response,
                                  
                                  gpointer user_data)
{
    if (!meta_http_response_is_successful(response)) {
        meta_debug("Failed to decline Instagram thread");
    }
}

/* ============================================================
 * User Operations
 * ============================================================ */

MetaUser *instagram_get_user_info(MetaAccount *account, const char *user_id)
{
    if (!account || !user_id) return NULL;
    
    return g_hash_table_lookup(account->users, user_id);
}

MetaUser *instagram_get_user_by_username(MetaAccount *account,
                                          const char *username)
{
    meta_debug("Looking up Instagram user: %s", username);
    return NULL;  /* TODO: Implement */
}

GList *instagram_search_users(MetaAccount *account, const char *query)
{
    meta_debug("Searching Instagram users: %s", query);
    return NULL;  /* TODO: Implement */
}

/* ============================================================
 * Presence
 * ============================================================ */

static void service_set_presence(MetaAccount *account, PurpleStatusPrimitive status)
{
    instagram_set_presence(account, status);
}

void instagram_set_presence(MetaAccount *account, PurpleStatusPrimitive status)
{
    /* Instagram has limited presence support */
    meta_debug("Instagram presence: %s (limited support)",
               purple_primitive_get_name_from_type(status));
}

/* ============================================================
 * Parsing Helpers
 * ============================================================ */

JsonObject *instagram_parse_response(const char *response, gsize len,
                                      gchar **error)
{
    JsonParser *parser;
    JsonObject *root;
    GError *parse_error = NULL;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, response, len, &parse_error)) {
        if (error) {
            *error = g_strdup(parse_error->message);
        }
        g_error_free(parse_error);
        g_object_unref(parser);
        return NULL;
    }
    
    root = json_node_dup_object(json_parser_get_root(parser));
    
    /* Check for API error */
    if (json_object_has_member(root, "status")) {
        const char *status = json_object_get_string_member(root, "status");
        if (g_strcmp0(status, "ok") != 0) {
            if (error && json_object_has_member(root, "message")) {
                *error = g_strdup(json_object_get_string_member(root, "message"));
            }
        }
    }
    
    g_object_unref(parser);
    return root;
}

GList *instagram_parse_inbox(const char *json_str)
{
    GList *threads = NULL;
    JsonParser *parser;
    JsonObject *root, *inbox;
    
    if (!json_str) return NULL;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, json_str, -1, NULL)) {
        g_object_unref(parser);
        return NULL;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    
    if (json_object_has_member(root, "inbox")) {
        inbox = json_object_get_object_member(root, "inbox");
        
        if (json_object_has_member(inbox, "threads")) {
            JsonArray *threads_array = json_object_get_array_member(inbox, "threads");
            guint count = json_array_get_length(threads_array);
            
            for (guint i = 0; i < count; i++) {
                JsonObject *thread_obj = json_array_get_object_element(threads_array, i);
                MetaThread *thread = instagram_parse_thread(thread_obj);
                if (thread) {
                    threads = g_list_append(threads, thread);
                }
            }
        }
    }
    
    g_object_unref(parser);
    return threads;
}

GList *instagram_parse_thread_items(const char *json_str)
{
    GList *items = NULL;
    JsonParser *parser;
    JsonObject *root, *thread;
    
    if (!json_str) return NULL;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, json_str, -1, NULL)) {
        g_object_unref(parser);
        return NULL;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    
    if (json_object_has_member(root, "thread")) {
        thread = json_object_get_object_member(root, "thread");
        
        if (json_object_has_member(thread, "items")) {
            JsonArray *items_array = json_object_get_array_member(thread, "items");
            guint count = json_array_get_length(items_array);
            
            for (guint i = 0; i < count; i++) {
                JsonObject *item_obj = json_array_get_object_element(items_array, i);
                MetaMessage *msg = instagram_parse_item(item_obj);
                if (msg) {
                    items = g_list_append(items, msg);
                }
            }
        }
    }
    
    g_object_unref(parser);
    return items;
}

MetaUser *instagram_parse_user(JsonObject *user_obj)
{
    MetaUser *user;
    
    if (!user_obj) return NULL;
    
    user = g_new0(MetaUser, 1);
    
    /* User ID - can be string or int in Instagram API */
    if (json_object_has_member(user_obj, "pk")) {
        user->id = g_strdup_printf("%lld",
            (long long)json_object_get_int_member(user_obj, "pk"));
    } else if (json_object_has_member(user_obj, "pk_id")) {
        user->id = g_strdup(json_object_get_string_member(user_obj, "pk_id"));
    }
    
    /* Username */
    user->username = g_strdup(
        json_object_get_string_member_with_default(user_obj, "username", ""));
    
    /* Display name - use full_name or fall back to username */
    const char *full_name = json_object_get_string_member_with_default(
        user_obj, "full_name", NULL);
    if (full_name && full_name[0] != '\0') {
        user->display_name = g_strdup(full_name);
    } else {
        user->display_name = g_strdup(user->username);
    }
    
    /* Avatar URL */
    user->avatar_url = g_strdup(
        json_object_get_string_member_with_default(
            user_obj, "profile_pic_url", NULL));
    
    return user;
}

MetaThread *instagram_parse_thread(JsonObject *thread_obj)
{
    MetaThread *thread;
    
    if (!thread_obj) return NULL;
    
    thread = g_new0(MetaThread, 1);
    
    thread->id = g_strdup(json_object_get_string_member(thread_obj, "thread_id"));
    thread->name = g_strdup(
        json_object_get_string_member_with_default(thread_obj, "thread_title", NULL));
    
    /* Determine if group */
    if (json_object_has_member(thread_obj, "thread_type")) {
        const char *type = json_object_get_string_member(thread_obj, "thread_type");
        thread->is_group = (g_strcmp0(type, "group") == 0);
    }
    
    /* Check if pending */
    thread->is_pending = json_object_get_boolean_member_with_default(
                            thread_obj, "pending", FALSE);
    
    /* Parse participants */
    if (json_object_has_member(thread_obj, "users")) {
        JsonArray *users = json_object_get_array_member(thread_obj, "users");
        guint count = json_array_get_length(users);
        
        for (guint i = 0; i < count; i++) {
            JsonObject *user_obj = json_array_get_object_element(users, i);
            MetaUser *user = instagram_parse_user(user_obj);
            if (user) {
                thread->participants = g_list_append(thread->participants, user);
            }
        }
    }
    
    /* Last activity */
    if (json_object_has_member(thread_obj, "last_activity_at")) {
        thread->last_activity = json_object_get_int_member(thread_obj, "last_activity_at");
    }
    
    /* Unread count */
    if (json_object_has_member(thread_obj, "read_state")) {
        /* Instagram uses different structure for unread */
    }
    
    /* Last message preview */
    if (json_object_has_member(thread_obj, "items")) {
        JsonArray *items = json_object_get_array_member(thread_obj, "items");
        if (json_array_get_length(items) > 0) {
            JsonObject *last_item = json_array_get_object_element(items, 0);
            if (json_object_has_member(last_item, "text")) {
                thread->last_message_preview = g_strdup(
                    json_object_get_string_member(last_item, "text"));
            }
        }
    }
    
    return thread;
}

MetaMessage *instagram_parse_item(JsonObject *item_obj)
{
    MetaMessage *msg;
    const char *item_type;
    
    if (!item_obj) return NULL;
    
    msg = g_new0(MetaMessage, 1);
    
    msg->id = g_strdup(json_object_get_string_member(item_obj, "item_id"));
    
    if (json_object_has_member(item_obj, "user_id")) {
        msg->sender_id = g_strdup_printf("%lld",
            (long long)json_object_get_int_member(item_obj, "user_id"));
    }
    
    msg->timestamp = json_object_get_int_member_with_default(item_obj, "timestamp", 0);
    
    /* Determine type and content */
    item_type = json_object_get_string_member_with_default(item_obj, "item_type", "text");
    
    if (g_strcmp0(item_type, "text") == 0) {
        msg->type = META_MSG_TEXT;
        msg->text = g_strdup(json_object_get_string_member_with_default(
                                item_obj, "text", ""));
    } else if (g_strcmp0(item_type, "media") == 0 ||
               g_strcmp0(item_type, "raven_media") == 0) {
        msg->type = META_MSG_IMAGE;
        if (json_object_has_member(item_obj, "media")) {
            JsonObject *media = json_object_get_object_member(item_obj, "media");
            if (json_object_has_member(media, "image_versions2")) {
                JsonObject *versions = json_object_get_object_member(media, "image_versions2");
                if (json_object_has_member(versions, "candidates")) {
                    JsonArray *candidates = json_object_get_array_member(versions, "candidates");
                    if (json_array_get_length(candidates) > 0) {
                        JsonObject *best = json_array_get_object_element(candidates, 0);
                        msg->media_url = g_strdup(
                            json_object_get_string_member(best, "url"));
                    }
                }
            }
        }
    } else if (g_strcmp0(item_type, "link") == 0) {
        msg->type = META_MSG_TEXT;  /* Treat links as text with URL */
        if (json_object_has_member(item_obj, "link")) {
            JsonObject *link = json_object_get_object_member(item_obj, "link");
            const char *link_text = json_object_get_string_member_with_default(link, "text", "");
            const char *link_url = json_object_get_string_member_with_default(link, "link_url", "");
            msg->text = g_strdup_printf("%s %s", link_text, link_url);
        }
    } else if (g_strcmp0(item_type, "like") == 0) {
        msg->type = META_MSG_REACTION;  /* Like is a reaction */
        msg->text = g_strdup("❤️");
    } else if (g_strcmp0(item_type, "voice_media") == 0) {
        msg->type = META_MSG_AUDIO;
        if (json_object_has_member(item_obj, "voice_media")) {
            JsonObject *voice = json_object_get_object_member(item_obj, "voice_media");
            if (json_object_has_member(voice, "media")) {
                JsonObject *media = json_object_get_object_member(voice, "media");
                if (json_object_has_member(media, "audio")) {
                    JsonObject *audio = json_object_get_object_member(media, "audio");
                    msg->media_url = g_strdup(
                        json_object_get_string_member(audio, "audio_src"));
                }
            }
        }
    } else if (g_strcmp0(item_type, "animated_media") == 0) {
        msg->type = META_MSG_STICKER;
        if (json_object_has_member(item_obj, "animated_media")) {
            JsonObject *anim = json_object_get_object_member(item_obj, "animated_media");
            if (json_object_has_member(anim, "images")) {
                JsonObject *images = json_object_get_object_member(anim, "images");
                if (json_object_has_member(images, "fixed_height")) {
                    JsonObject *fixed = json_object_get_object_member(images, "fixed_height");
                    msg->media_url = g_strdup(
                        json_object_get_string_member(fixed, "url"));
                }
            }
        }
    } else {
        /* Unknown type - treat as text with type indicator */
        msg->type = META_MSG_TEXT;
        msg->text = g_strdup_printf("[%s]", item_type);
    }
    
    /* Check for reactions - store first reaction emoji if present */
    if (json_object_has_member(item_obj, "reactions")) {
        JsonObject *reactions = json_object_get_object_member(item_obj, "reactions");
        if (json_object_has_member(reactions, "emojis")) {
            JsonArray *emojis = json_object_get_array_member(reactions, "emojis");
            if (json_array_get_length(emojis) > 0) {
                JsonObject *emoji = json_array_get_object_element(emojis, 0);
                const char *e = json_object_get_string_member(emoji, "emoji");
                if (e) {
                    msg->reaction_emoji = g_strdup(e);
                }
            }
        }
    }
    
    return msg;
}

/* ============================================================
 * Cleanup
 * ============================================================ */

void instagram_free_user(MetaUser *user)
{
    if (!user) return;
    
    g_free(user->id);
    g_free(user->username);
    g_free(user->display_name);
    g_free(user->avatar_url);
    g_free(user);
}

void instagram_free_thread(MetaThread *thread)
{
    if (!thread) return;
    
    g_free(thread->id);
    g_free(thread->name);
    g_free(thread->last_message_preview);
    
    g_list_free_full(thread->participants, (GDestroyNotify)instagram_free_user);
    
    g_free(thread);
}

void instagram_free_message(MetaMessage *msg)
{
    if (!msg) return;
    
    g_free(msg->id);
    g_free(msg->sender_id);
    g_free(msg->text);
    g_free(msg->media_url);
    g_free(msg->reaction_emoji);
    g_free(msg);
}