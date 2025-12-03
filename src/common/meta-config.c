/**
 * meta-config.c
 * 
 * External configuration module implementation for libpurple-meta
 * Allows updating endpoints and settings without recompiling
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#include "meta-config.h"
#include <json-glib/json-glib.h>
#include <string.h>

/* Global configuration instance */
static MetaConfig *global_config = NULL;
static gboolean config_loaded = FALSE;

/* ============================================================
 * Internal Helpers
 * ============================================================ */

static const gchar *json_get_string(JsonObject *obj, const char *member,
                                     const char *default_val)
{
    if (json_object_has_member(obj, member)) {
        return json_object_get_string_member(obj, member);
    }
    return default_val;
}

static gint64 json_get_int(JsonObject *obj, const char *member, gint64 default_val)
{
    if (json_object_has_member(obj, member)) {
        return json_object_get_int_member(obj, member);
    }
    return default_val;
}

static gboolean json_get_bool(JsonObject *obj, const char *member, gboolean default_val)
{
    if (json_object_has_member(obj, member)) {
        return json_object_get_boolean_member(obj, member);
    }
    return default_val;
}

/* ============================================================
 * Path Helpers
 * ============================================================ */

gchar *meta_config_get_user_path(void)
{
    const gchar *purple_dir = purple_user_dir();
    return g_build_filename(purple_dir, META_CONFIG_FILENAME, NULL);
}

gchar *meta_config_get_system_path(void)
{
#ifdef _WIN32
    return g_build_filename(g_get_system_config_dirs()[0], "purple", 
                            META_CONFIG_FILENAME, NULL);
#else
    return g_build_filename("/etc", "purple", META_CONFIG_FILENAME, NULL);
#endif
}

/* ============================================================
 * Default Configuration
 * ============================================================ */

MetaConfig *meta_config_create_default(void)
{
    MetaConfig *config = g_new0(MetaConfig, 1);
    
    config->version = META_CONFIG_VERSION;
    config->last_updated = 0;
    config->update_url = g_strdup(META_CONFIG_UPDATE_URL);
    config->loaded_from = NULL;
    
    /* Messenger defaults */
    config->messenger.oauth_auth_url = g_strdup(META_DEFAULT_OAUTH_AUTH_URL);
    config->messenger.oauth_token_url = g_strdup(META_DEFAULT_OAUTH_TOKEN_URL);
    config->messenger.graph_api_base = g_strdup(META_DEFAULT_GRAPH_API_BASE);
    config->messenger.mqtt_endpoint = g_strdup(META_DEFAULT_MQTT_ENDPOINT);
    config->messenger.mqtt_origin = g_strdup(META_DEFAULT_MQTT_ORIGIN);
    config->messenger.graph_api_version = g_strdup(META_DEFAULT_GRAPH_API_VERSION);
    config->messenger.oauth_client_id = g_strdup("YOUR_META_APP_ID");
    config->messenger.oauth_redirect_uri = g_strdup("https://localhost/oauth/callback");
    config->messenger.oauth_scope = g_strdup("pages_messaging,pages_read_engagement");
    config->messenger.rate_limit_calls = 200;
    config->messenger.rate_limit_window = 3600;
    config->messenger.min_request_interval_ms = 100;
    
    /* Instagram defaults */
    config->instagram.api_base = g_strdup(META_DEFAULT_IG_API_BASE);
    config->instagram.graphql_api = g_strdup(META_DEFAULT_IG_GRAPHQL_API);
    config->instagram.realtime_url = g_strdup(META_DEFAULT_IG_REALTIME_URL);
    config->instagram.upload_url = g_strdup(META_DEFAULT_IG_UPLOAD_URL);
    config->instagram.app_version = g_strdup(META_DEFAULT_IG_APP_VERSION);
    config->instagram.version_code = g_strdup(META_DEFAULT_IG_VERSION_CODE);
    config->instagram.sig_key_version = g_strdup("4");
    config->instagram.user_agent = g_strdup_printf(
        "Instagram %s Android (30/11; 420dpi; 1080x2220; samsung; SM-G975F; "
        "beyond2; exynos9820; en_US; %s)",
        META_DEFAULT_IG_APP_VERSION, META_DEFAULT_IG_VERSION_CODE);
    config->instagram.device_manufacturer = g_strdup("samsung");
    config->instagram.device_model = g_strdup("SM-G975F");
    config->instagram.android_version = g_strdup("30");
    config->instagram.android_release = g_strdup("11");
    config->instagram.rate_limit_calls = 100;
    config->instagram.rate_limit_window = 3600;
    config->instagram.min_request_interval_ms = 200;
    config->instagram.x_ig_capabilities = g_strdup("3brTvwE=");
    config->instagram.x_ig_connection_type = g_strdup("WIFI");
    config->instagram.x_ig_app_id = g_strdup("567067343352427");
    
    /* WebSocket defaults */
    config->websocket.connect_timeout = 30;
    config->websocket.ping_interval = 30;
    config->websocket.pong_timeout = 10;
    config->websocket.reconnect_delay = 5;
    config->websocket.max_reconnect_delay = 300;
    config->websocket.max_reconnect_attempts = 10;
    config->websocket.topic_messages = g_strdup("/t_ms");
    config->websocket.topic_message_sync = g_strdup("/messaging_events");
    config->websocket.topic_typing = g_strdup("/typing");
    config->websocket.topic_presence = g_strdup("/presence");
    config->websocket.topic_read_receipts = g_strdup("/t_rt");
    config->websocket.topic_thread_updates = g_strdup("/thread_updates");
    config->websocket.ig_topic_direct = g_strdup("/ig_direct");
    config->websocket.ig_topic_message_sync = g_strdup("/ig_message_sync");
    config->websocket.ig_topic_realtime = g_strdup("/ig_realtime_sub");
    
    /* Security defaults */
    config->security.warn_plaintext_storage = TRUE;
    config->security.obfuscate_tokens = TRUE;
    config->security.max_token_age = 86400;
    config->security.max_failed_logins = 5;
    config->security.login_lockout_duration = 3600;
    config->security.require_tls_1_2 = TRUE;
    config->security.verify_certificates = TRUE;
    config->security.initial_backoff = 1;
    config->security.max_backoff = 600;
    config->security.backoff_multiplier = 2;
    
    /* Feature flags - all enabled by default */
    config->features.messenger_enabled = TRUE;
    config->features.instagram_enabled = TRUE;
    config->features.presence_enabled = TRUE;
    config->features.typing_enabled = TRUE;
    config->features.read_receipts_enabled = TRUE;
    config->features.reactions_enabled = TRUE;
    config->features.attachments_enabled = TRUE;
    config->features.group_chats_enabled = TRUE;
    config->features.ig_pending_inbox_enabled = TRUE;
    config->features.ig_disappearing_enabled = TRUE;
    config->features.ig_voice_enabled = TRUE;
    
    /* Debug settings */
    config->debug_mode = FALSE;
    config->log_api_calls = FALSE;
    config->log_websocket = FALSE;
    
    return config;
}

/* ============================================================
 * Configuration Loading
 * ============================================================ */

static void parse_messenger_config(JsonObject *obj, MetaMessengerConfig *config)
{
    if (!obj) return;
    
    g_free(config->oauth_auth_url);
    config->oauth_auth_url = g_strdup(json_get_string(obj, "oauth_auth_url",
                                       META_DEFAULT_OAUTH_AUTH_URL));
    
    g_free(config->oauth_token_url);
    config->oauth_token_url = g_strdup(json_get_string(obj, "oauth_token_url",
                                        META_DEFAULT_OAUTH_TOKEN_URL));
    
    g_free(config->graph_api_base);
    config->graph_api_base = g_strdup(json_get_string(obj, "graph_api_base",
                                       META_DEFAULT_GRAPH_API_BASE));
    
    g_free(config->mqtt_endpoint);
    config->mqtt_endpoint = g_strdup(json_get_string(obj, "mqtt_endpoint",
                                      META_DEFAULT_MQTT_ENDPOINT));
    
    g_free(config->mqtt_origin);
    config->mqtt_origin = g_strdup(json_get_string(obj, "mqtt_origin",
                                    META_DEFAULT_MQTT_ORIGIN));
    
    g_free(config->graph_api_version);
    config->graph_api_version = g_strdup(json_get_string(obj, "graph_api_version",
                                          META_DEFAULT_GRAPH_API_VERSION));
    
    if (json_object_has_member(obj, "oauth_client_id")) {
        g_free(config->oauth_client_id);
        config->oauth_client_id = g_strdup(json_get_string(obj, "oauth_client_id", ""));
    }
    
    if (json_object_has_member(obj, "oauth_redirect_uri")) {
        g_free(config->oauth_redirect_uri);
        config->oauth_redirect_uri = g_strdup(json_get_string(obj, "oauth_redirect_uri", ""));
    }
    
    if (json_object_has_member(obj, "oauth_scope")) {
        g_free(config->oauth_scope);
        config->oauth_scope = g_strdup(json_get_string(obj, "oauth_scope", ""));
    }
    
    config->rate_limit_calls = (guint)json_get_int(obj, "rate_limit_calls", 200);
    config->rate_limit_window = (guint)json_get_int(obj, "rate_limit_window", 3600);
    config->min_request_interval_ms = (guint)json_get_int(obj, "min_request_interval_ms", 100);
}

static void parse_instagram_config(JsonObject *obj, MetaInstagramConfig *config)
{
    if (!obj) return;
    
    g_free(config->api_base);
    config->api_base = g_strdup(json_get_string(obj, "api_base",
                                 META_DEFAULT_IG_API_BASE));
    
    g_free(config->graphql_api);
    config->graphql_api = g_strdup(json_get_string(obj, "graphql_api",
                                    META_DEFAULT_IG_GRAPHQL_API));
    
    g_free(config->realtime_url);
    config->realtime_url = g_strdup(json_get_string(obj, "realtime_url",
                                     META_DEFAULT_IG_REALTIME_URL));
    
    g_free(config->upload_url);
    config->upload_url = g_strdup(json_get_string(obj, "upload_url",
                                   META_DEFAULT_IG_UPLOAD_URL));
    
    g_free(config->app_version);
    config->app_version = g_strdup(json_get_string(obj, "app_version",
                                    META_DEFAULT_IG_APP_VERSION));
    
    g_free(config->version_code);
    config->version_code = g_strdup(json_get_string(obj, "version_code",
                                     META_DEFAULT_IG_VERSION_CODE));
    
    if (json_object_has_member(obj, "user_agent")) {
        g_free(config->user_agent);
        config->user_agent = g_strdup(json_get_string(obj, "user_agent", ""));
    }
    
    if (json_object_has_member(obj, "device_manufacturer")) {
        g_free(config->device_manufacturer);
        config->device_manufacturer = g_strdup(json_get_string(obj, "device_manufacturer", "samsung"));
    }
    
    if (json_object_has_member(obj, "device_model")) {
        g_free(config->device_model);
        config->device_model = g_strdup(json_get_string(obj, "device_model", "SM-G975F"));
    }
    
    config->rate_limit_calls = (guint)json_get_int(obj, "rate_limit_calls", 100);
    config->rate_limit_window = (guint)json_get_int(obj, "rate_limit_window", 3600);
    config->min_request_interval_ms = (guint)json_get_int(obj, "min_request_interval_ms", 200);
    
    if (json_object_has_member(obj, "x_ig_capabilities")) {
        g_free(config->x_ig_capabilities);
        config->x_ig_capabilities = g_strdup(json_get_string(obj, "x_ig_capabilities", "3brTvwE="));
    }
    
    if (json_object_has_member(obj, "x_ig_app_id")) {
        g_free(config->x_ig_app_id);
        config->x_ig_app_id = g_strdup(json_get_string(obj, "x_ig_app_id", "567067343352427"));
    }
}

static void parse_websocket_config(JsonObject *obj, MetaWebSocketConfig *config)
{
    if (!obj) return;
    
    config->connect_timeout = (guint)json_get_int(obj, "connect_timeout", 30);
    config->ping_interval = (guint)json_get_int(obj, "ping_interval", 30);
    config->pong_timeout = (guint)json_get_int(obj, "pong_timeout", 10);
    config->reconnect_delay = (guint)json_get_int(obj, "reconnect_delay", 5);
    config->max_reconnect_delay = (guint)json_get_int(obj, "max_reconnect_delay", 300);
    config->max_reconnect_attempts = (guint)json_get_int(obj, "max_reconnect_attempts", 10);
    
    if (json_object_has_member(obj, "topic_messages")) {
        g_free(config->topic_messages);
        config->topic_messages = g_strdup(json_get_string(obj, "topic_messages", "/t_ms"));
    }
    
    if (json_object_has_member(obj, "topic_typing")) {
        g_free(config->topic_typing);
        config->topic_typing = g_strdup(json_get_string(obj, "topic_typing", "/typing"));
    }
    
    if (json_object_has_member(obj, "topic_presence")) {
        g_free(config->topic_presence);
        config->topic_presence = g_strdup(json_get_string(obj, "topic_presence", "/presence"));
    }
}

static void parse_security_config(JsonObject *obj, MetaSecurityConfig *config)
{
    if (!obj) return;
    
    config->warn_plaintext_storage = json_get_bool(obj, "warn_plaintext_storage", TRUE);
    config->obfuscate_tokens = json_get_bool(obj, "obfuscate_tokens", TRUE);
    config->max_token_age = (guint)json_get_int(obj, "max_token_age", 86400);
    config->max_failed_logins = (guint)json_get_int(obj, "max_failed_logins", 5);
    config->login_lockout_duration = (guint)json_get_int(obj, "login_lockout_duration", 3600);
    config->require_tls_1_2 = json_get_bool(obj, "require_tls_1_2", TRUE);
    config->verify_certificates = json_get_bool(obj, "verify_certificates", TRUE);
    config->initial_backoff = (guint)json_get_int(obj, "initial_backoff", 1);
    config->max_backoff = (guint)json_get_int(obj, "max_backoff", 600);
    config->backoff_multiplier = (guint)json_get_int(obj, "backoff_multiplier", 2);
}

static void parse_feature_flags(JsonObject *obj, MetaFeatureFlags *config)
{
    if (!obj) return;
    
    config->messenger_enabled = json_get_bool(obj, "messenger_enabled", TRUE);
    config->instagram_enabled = json_get_bool(obj, "instagram_enabled", TRUE);
    config->presence_enabled = json_get_bool(obj, "presence_enabled", TRUE);
    config->typing_enabled = json_get_bool(obj, "typing_enabled", TRUE);
    config->read_receipts_enabled = json_get_bool(obj, "read_receipts_enabled", TRUE);
    config->reactions_enabled = json_get_bool(obj, "reactions_enabled", TRUE);
    config->attachments_enabled = json_get_bool(obj, "attachments_enabled", TRUE);
    config->group_chats_enabled = json_get_bool(obj, "group_chats_enabled", TRUE);
    config->ig_pending_inbox_enabled = json_get_bool(obj, "ig_pending_inbox_enabled", TRUE);
    config->ig_disappearing_enabled = json_get_bool(obj, "ig_disappearing_enabled", TRUE);
    config->ig_voice_enabled = json_get_bool(obj, "ig_voice_enabled", TRUE);
}

MetaConfig *meta_config_load_json(const char *json)
{
    MetaConfig *config;
    JsonParser *parser;
    JsonObject *root;
    GError *error = NULL;
    
    if (!json) return NULL;
    
    /* Start with defaults */
    config = meta_config_create_default();
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, json, -1, &error)) {
        purple_debug_warning("prpl-meta", "Failed to parse config JSON: %s\n",
                            error ? error->message : "unknown");
        if (error) g_error_free(error);
        g_object_unref(parser);
        return config;  /* Return defaults */
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    if (!root) {
        g_object_unref(parser);
        return config;
    }
    
    /* Parse version */
    config->version = (gint)json_get_int(root, "version", META_CONFIG_VERSION);
    config->last_updated = json_get_int(root, "last_updated", 0);
    
    if (json_object_has_member(root, "update_url")) {
        g_free(config->update_url);
        config->update_url = g_strdup(json_get_string(root, "update_url", ""));
    }
    
    /* Parse sections */
    if (json_object_has_member(root, "messenger")) {
        parse_messenger_config(json_object_get_object_member(root, "messenger"),
                              &config->messenger);
    }
    
    if (json_object_has_member(root, "instagram")) {
        parse_instagram_config(json_object_get_object_member(root, "instagram"),
                              &config->instagram);
    }
    
    if (json_object_has_member(root, "websocket")) {
        parse_websocket_config(json_object_get_object_member(root, "websocket"),
                              &config->websocket);
    }
    
    if (json_object_has_member(root, "security")) {
        parse_security_config(json_object_get_object_member(root, "security"),
                             &config->security);
    }
    
    if (json_object_has_member(root, "features")) {
        parse_feature_flags(json_object_get_object_member(root, "features"),
                           &config->features);
    }
    
    /* Debug settings */
    config->debug_mode = json_get_bool(root, "debug_mode", FALSE);
    config->log_api_calls = json_get_bool(root, "log_api_calls", FALSE);
    config->log_websocket = json_get_bool(root, "log_websocket", FALSE);
    
    g_object_unref(parser);
    
    return config;
}

MetaConfig *meta_config_load_file(const char *filepath)
{
    MetaConfig *config;
    gchar *contents;
    gsize length;
    GError *error = NULL;
    
    if (!filepath) return NULL;
    
    if (!g_file_get_contents(filepath, &contents, &length, &error)) {
        purple_debug_info("prpl-meta", "Could not load config from %s: %s\n",
                         filepath, error ? error->message : "unknown");
        if (error) g_error_free(error);
        return NULL;
    }
    
    config = meta_config_load_json(contents);
    g_free(contents);
    
    if (config) {
        config->loaded_from = g_strdup(filepath);
        purple_debug_info("prpl-meta", "Loaded configuration from %s\n", filepath);
    }
    
    return config;
}

/* ============================================================
 * Global Configuration Access
 * ============================================================ */

MetaConfig *meta_config_get(void)
{
    gchar *user_path;
    gchar *system_path;
    
    if (config_loaded && global_config) {
        return global_config;
    }
    
    /* Try to load from user config first */
    user_path = meta_config_get_user_path();
    global_config = meta_config_load_file(user_path);
    g_free(user_path);
    
    if (!global_config) {
        /* Try system config */
        system_path = meta_config_get_system_path();
        global_config = meta_config_load_file(system_path);
        g_free(system_path);
    }
    
    if (!global_config) {
        /* Use defaults */
        global_config = meta_config_create_default();
        purple_debug_info("prpl-meta", "Using default configuration\n");
    }
    
    config_loaded = TRUE;
    
    return global_config;
}

gboolean meta_config_reload(void)
{
    if (global_config) {
        meta_config_destroy(global_config);
        global_config = NULL;
    }
    config_loaded = FALSE;
    
    meta_config_get();
    
    return (global_config != NULL);
}

void meta_config_free(void)
{
    if (global_config) {
        meta_config_destroy(global_config);
        global_config = NULL;
    }
    config_loaded = FALSE;
}

/* ============================================================
 * Configuration Saving
 * ============================================================ */

gchar *meta_config_to_json(MetaConfig *config)
{
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    
    if (!config) return NULL;
    
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    /* Version info */
    json_builder_set_member_name(builder, "version");
    json_builder_add_int_value(builder, config->version);
    
    json_builder_set_member_name(builder, "last_updated");
    json_builder_add_int_value(builder, (gint64)time(NULL));
    
    if (config->update_url) {
        json_builder_set_member_name(builder, "update_url");
        json_builder_add_string_value(builder, config->update_url);
    }
    
    /* Messenger section */
    json_builder_set_member_name(builder, "messenger");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "oauth_auth_url");
    json_builder_add_string_value(builder, config->messenger.oauth_auth_url);
    json_builder_set_member_name(builder, "oauth_token_url");
    json_builder_add_string_value(builder, config->messenger.oauth_token_url);
    json_builder_set_member_name(builder, "graph_api_base");
    json_builder_add_string_value(builder, config->messenger.graph_api_base);
    json_builder_set_member_name(builder, "mqtt_endpoint");
    json_builder_add_string_value(builder, config->messenger.mqtt_endpoint);
    json_builder_set_member_name(builder, "graph_api_version");
    json_builder_add_string_value(builder, config->messenger.graph_api_version);
    json_builder_set_member_name(builder, "rate_limit_calls");
    json_builder_add_int_value(builder, config->messenger.rate_limit_calls);
    json_builder_set_member_name(builder, "rate_limit_window");
    json_builder_add_int_value(builder, config->messenger.rate_limit_window);
    json_builder_end_object(builder);
    
    /* Instagram section */
    json_builder_set_member_name(builder, "instagram");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "api_base");
    json_builder_add_string_value(builder, config->instagram.api_base);
    json_builder_set_member_name(builder, "graphql_api");
    json_builder_add_string_value(builder, config->instagram.graphql_api);
    json_builder_set_member_name(builder, "realtime_url");
    json_builder_add_string_value(builder, config->instagram.realtime_url);
    json_builder_set_member_name(builder, "app_version");
    json_builder_add_string_value(builder, config->instagram.app_version);
    json_builder_set_member_name(builder, "version_code");
    json_builder_add_string_value(builder, config->instagram.version_code);
    json_builder_set_member_name(builder, "rate_limit_calls");
    json_builder_add_int_value(builder, config->instagram.rate_limit_calls);
    json_builder_set_member_name(builder, "rate_limit_window");
    json_builder_add_int_value(builder, config->instagram.rate_limit_window);
    json_builder_end_object(builder);
    
    /* WebSocket section */
    json_builder_set_member_name(builder, "websocket");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "connect_timeout");
    json_builder_add_int_value(builder, config->websocket.connect_timeout);
    json_builder_set_member_name(builder, "ping_interval");
    json_builder_add_int_value(builder, config->websocket.ping_interval);
    json_builder_set_member_name(builder, "reconnect_delay");
    json_builder_add_int_value(builder, config->websocket.reconnect_delay);
    json_builder_set_member_name(builder, "max_reconnect_delay");
    json_builder_add_int_value(builder, config->websocket.max_reconnect_delay);
    json_builder_end_object(builder);
    
    /* Security section */
    json_builder_set_member_name(builder, "security");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "warn_plaintext_storage");
    json_builder_add_boolean_value(builder, config->security.warn_plaintext_storage);
    json_builder_set_member_name(builder, "obfuscate_tokens");
    json_builder_add_boolean_value(builder, config->security.obfuscate_tokens);
    json_builder_set_member_name(builder, "max_token_age");
    json_builder_add_int_value(builder, config->security.max_token_age);
    json_builder_set_member_name(builder, "initial_backoff");
    json_builder_add_int_value(builder, config->security.initial_backoff);
    json_builder_set_member_name(builder, "max_backoff");
    json_builder_add_int_value(builder, config->security.max_backoff);
    json_builder_end_object(builder);
    
    /* Features section */
    json_builder_set_member_name(builder, "features");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "messenger_enabled");
    json_builder_add_boolean_value(builder, config->features.messenger_enabled);
    json_builder_set_member_name(builder, "instagram_enabled");
    json_builder_add_boolean_value(builder, config->features.instagram_enabled);
    json_builder_set_member_name(builder, "presence_enabled");
    json_builder_add_boolean_value(builder, config->features.presence_enabled);
    json_builder_set_member_name(builder, "typing_enabled");
    json_builder_add_boolean_value(builder, config->features.typing_enabled);
    json_builder_set_member_name(builder, "reactions_enabled");
    json_builder_add_boolean_value(builder, config->features.reactions_enabled);
    json_builder_set_member_name(builder, "attachments_enabled");
    json_builder_add_boolean_value(builder, config->features.attachments_enabled);
    json_builder_end_object(builder);
    
    /* Debug settings */
    json_builder_set_member_name(builder, "debug_mode");
    json_builder_add_boolean_value(builder, config->debug_mode);
    json_builder_set_member_name(builder, "log_api_calls");
    json_builder_add_boolean_value(builder, config->log_api_calls);
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_pretty(gen, TRUE);
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    g_object_unref(gen);
    g_object_unref(builder);
    
    return json_str;
}

gboolean meta_config_save_file(MetaConfig *config, const char *filepath)
{
    gchar *json_str;
    gboolean result;
    GError *error = NULL;
    
    if (!config || !filepath) return FALSE;
    
    json_str = meta_config_to_json(config);
    if (!json_str) return FALSE;
    
    result = g_file_set_contents(filepath, json_str, -1, &error);
    
    if (!result) {
        purple_debug_error("prpl-meta", "Failed to save config to %s: %s\n",
                          filepath, error ? error->message : "unknown");
        if (error) g_error_free(error);
    } else {
        purple_debug_info("prpl-meta", "Configuration saved to %s\n", filepath);
    }
    
    g_free(json_str);
    
    return result;
}

/* ============================================================
 * Convenience Getters
 * ============================================================ */

const gchar *meta_config_get_oauth_auth_url(void)
{
    MetaConfig *config = meta_config_get();
    return config->messenger.oauth_auth_url;
}

const gchar *meta_config_get_oauth_token_url(void)
{
    MetaConfig *config = meta_config_get();
    return config->messenger.oauth_token_url;
}

const gchar *meta_config_get_graph_api_base(void)
{
    MetaConfig *config = meta_config_get();
    return config->messenger.graph_api_base;
}

const gchar *meta_config_get_mqtt_endpoint(void)
{
    MetaConfig *config = meta_config_get();
    return config->messenger.mqtt_endpoint;
}

const gchar *meta_config_get_mqtt_origin(void)
{
    MetaConfig *config = meta_config_get();
    return config->messenger.mqtt_origin;
}

const gchar *meta_config_get_ig_api_base(void)
{
    MetaConfig *config = meta_config_get();
    return config->instagram.api_base;
}

const gchar *meta_config_get_ig_graphql_api(void)
{
    MetaConfig *config = meta_config_get();
    return config->instagram.graphql_api;
}

const gchar *meta_config_get_ig_realtime_url(void)
{
    MetaConfig *config = meta_config_get();
    return config->instagram.realtime_url;
}

const gchar *meta_config_get_ig_upload_url(void)
{
    MetaConfig *config = meta_config_get();
    return config->instagram.upload_url;
}

const gchar *meta_config_get_ig_user_agent(void)
{
    MetaConfig *config = meta_config_get();
    return config->instagram.user_agent;
}

guint meta_config_get_ws_connect_timeout(void)
{
    MetaConfig *config = meta_config_get();
    return config->websocket.connect_timeout;
}

guint meta_config_get_ws_ping_interval(void)
{
    MetaConfig *config = meta_config_get();
    return config->websocket.ping_interval;
}

guint meta_config_get_ws_reconnect_delay(void)
{
    MetaConfig *config = meta_config_get();
    return config->websocket.reconnect_delay;
}

gboolean meta_config_is_messenger_enabled(void)
{
    MetaConfig *config = meta_config_get();
    return config->features.messenger_enabled;
}

gboolean meta_config_is_instagram_enabled(void)
{
    MetaConfig *config = meta_config_get();
    return config->features.instagram_enabled;
}

gboolean meta_config_is_feature_enabled(const char *feature_name)
{
    MetaConfig *config = meta_config_get();
    
    if (g_strcmp0(feature_name, "messenger") == 0)
        return config->features.messenger_enabled;
    if (g_strcmp0(feature_name, "instagram") == 0)
        return config->features.instagram_enabled;
    if (g_strcmp0(feature_name, "presence") == 0)
        return config->features.presence_enabled;
    if (g_strcmp0(feature_name, "typing") == 0)
        return config->features.typing_enabled;
    if (g_strcmp0(feature_name, "read_receipts") == 0)
        return config->features.read_receipts_enabled;
    if (g_strcmp0(feature_name, "reactions") == 0)
        return config->features.reactions_enabled;
    if (g_strcmp0(feature_name, "attachments") == 0)
        return config->features.attachments_enabled;
    if (g_strcmp0(feature_name, "group_chats") == 0)
        return config->features.group_chats_enabled;
    
    return TRUE;  /* Unknown features are enabled by default */
}

guint meta_config_get_rate_limit_calls(gboolean is_instagram)
{
    MetaConfig *config = meta_config_get();
    return is_instagram ? config->instagram.rate_limit_calls 
                        : config->messenger.rate_limit_calls;
}

guint meta_config_get_rate_limit_window(gboolean is_instagram)
{
    MetaConfig *config = meta_config_get();
    return is_instagram ? config->instagram.rate_limit_window
                        : config->messenger.rate_limit_window;
}

guint meta_config_get_min_request_interval(gboolean is_instagram)
{
    MetaConfig *config = meta_config_get();
    return is_instagram ? config->instagram.min_request_interval_ms
                        : config->messenger.min_request_interval_ms;
}

/* ============================================================
 * Dynamic URL Building
 * ============================================================ */

gchar *meta_config_build_graph_url(const char *endpoint)
{
    MetaConfig *config = meta_config_get();
    
    if (!endpoint) return NULL;
    
    if (endpoint[0] == '/') {
        return g_strdup_printf("%s%s", config->messenger.graph_api_base, endpoint);
    }
    return g_strdup_printf("%s/%s", config->messenger.graph_api_base, endpoint);
}

gchar *meta_config_build_ig_url(const char *endpoint)
{
    MetaConfig *config = meta_config_get();
    
    if (!endpoint) return NULL;
    
    if (endpoint[0] == '/') {
        return g_strdup_printf("%s%s", config->instagram.api_base, endpoint);
    }
    return g_strdup_printf("%s/%s", config->instagram.api_base, endpoint);
}

GHashTable *meta_config_get_ig_headers(void)
{
    MetaConfig *config = meta_config_get();
    GHashTable *headers = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                 g_free, g_free);
    
    g_hash_table_insert(headers, g_strdup("User-Agent"),
                        g_strdup(config->instagram.user_agent));
    g_hash_table_insert(headers, g_strdup("X-IG-Capabilities"),
                        g_strdup(config->instagram.x_ig_capabilities));
    g_hash_table_insert(headers, g_strdup("X-IG-Connection-Type"),
                        g_strdup(config->instagram.x_ig_connection_type));
    g_hash_table_insert(headers, g_strdup("X-IG-App-ID"),
                        g_strdup(config->instagram.x_ig_app_id));
    g_hash_table_insert(headers, g_strdup("Accept-Language"),
                        g_strdup("en-US"));
    g_hash_table_insert(headers, g_strdup("Content-Type"),
                        g_strdup("application/x-www-form-urlencoded; charset=UTF-8"));
    
    return headers;
}

/* ============================================================
 * Memory Management
 * ============================================================ */

void meta_config_destroy(MetaConfig *config)
{
    if (!config) return;
    
    /* Free update URL */
    g_free(config->update_url);
    g_free(config->loaded_from);
    
    /* Free Messenger config */
    g_free(config->messenger.oauth_auth_url);
    g_free(config->messenger.oauth_token_url);
    g_free(config->messenger.graph_api_base);
    g_free(config->messenger.mqtt_endpoint);
    g_free(config->messenger.mqtt_origin);
    g_free(config->messenger.graph_api_version);
    g_free(config->messenger.oauth_client_id);
    g_free(config->messenger.oauth_redirect_uri);
    g_free(config->messenger.oauth_scope);
    
    /* Free Instagram config */
    g_free(config->instagram.api_base);
    g_free(config->instagram.graphql_api);
    g_free(config->instagram.realtime_url);
    g_free(config->instagram.upload_url);
    g_free(config->instagram.app_version);
    g_free(config->instagram.version_code);
    g_free(config->instagram.sig_key_version);
    g_free(config->instagram.user_agent);
    g_free(config->instagram.device_manufacturer);
    g_free(config->instagram.device_model);
    g_free(config->instagram.android_version);
    g_free(config->instagram.android_release);
    g_free(config->instagram.x_ig_capabilities);
    g_free(config->instagram.x_ig_connection_type);
    g_free(config->instagram.x_ig_app_id);
    
    /* Free WebSocket config */
    g_free(config->websocket.topic_messages);
    g_free(config->websocket.topic_message_sync);
    g_free(config->websocket.topic_typing);
    g_free(config->websocket.topic_presence);
    g_free(config->websocket.topic_read_receipts);
    g_free(config->websocket.topic_thread_updates);
    g_free(config->websocket.ig_topic_direct);
    g_free(config->websocket.ig_topic_message_sync);
    g_free(config->websocket.ig_topic_realtime);
    
    g_free(config);
}

MetaConfig *meta_config_copy(MetaConfig *config)
{
    gchar *json;
    MetaConfig *copy;
    
    if (!config) return NULL;
    
    json = meta_config_to_json(config);
    copy = meta_config_load_json(json);
    g_free(json);
    
    return copy;
}

gboolean meta_config_validate(MetaConfig *config, gchar **error)
{
    if (!config) {
        if (error) *error = g_strdup("Configuration is NULL");
        return FALSE;
    }
    
    /* Check required URLs */
    if (!config->messenger.oauth_auth_url || !config->messenger.graph_api_base) {
        if (error) *error = g_strdup("Missing required Messenger URLs");
        return FALSE;
    }
    
    if (!config->instagram.api_base) {
        if (error) *error = g_strdup("Missing required Instagram URL");
        return FALSE;
    }
    
    /* Validate rate limits */
    if (config->messenger.rate_limit_calls == 0 || 
        config->messenger.rate_limit_window == 0) {
        if (error) *error = g_strdup("Invalid Messenger rate limit settings");
        return FALSE;
    }
    
    if (config->instagram.rate_limit_calls == 0 ||
        config->instagram.rate_limit_window == 0) {
        if (error) *error = g_strdup("Invalid Instagram rate limit settings");
        return FALSE;
    }
    
    /* Validate WebSocket settings */
    if (config->websocket.ping_interval < 5 || 
        config->websocket.ping_interval > 300) {
        if (error) *error = g_strdup("Ping interval must be between 5 and 300 seconds");
        return FALSE;
    }
    
    return TRUE;
}

void meta_config_check_update_async(GCallback callback, gpointer user_data)
{
    /* This would download the latest config from the update URL
     * and compare versions. For now, just log that it was called. */
    purple_debug_info("prpl-meta", "Config update check requested\n");
    
    /* In a full implementation, this would:
     * 1. Fetch META_CONFIG_UPDATE_URL
     * 2. Parse the JSON
     * 3. Compare versions
     * 4. Notify user if update available
     * 5. Optionally auto-update
     */
}