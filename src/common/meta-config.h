/**
 * meta-config.h
 * 
 * External configuration module for libpurple-meta
 * Allows updating endpoints and settings without recompiling
 * 
 * Configuration file locations (searched in order):
 * 1. ~/.purple/meta-config.json (user override)
 * 2. /etc/purple/meta-config.json (system-wide)
 * 3. Built-in defaults (this file)
 * 
 * This addresses the maintenance burden of reverse-engineered protocols
 * where endpoints change frequently.
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef META_CONFIG_H
#define META_CONFIG_H

#include <glib.h>
#include <purple.h>

/* Configuration file name */
#define META_CONFIG_FILENAME        "meta-config.json"
#define META_CONFIG_VERSION         1

/* Update check URL (optional - for notifying users of config updates) */
#define META_CONFIG_UPDATE_URL      "https://raw.githubusercontent.com/libpurple-meta/libpurple-meta/main/config/meta-config.json"
#define META_CONFIG_UPDATE_CHECK_INTERVAL  86400  /* 24 hours */

/* ============================================================
 * Default Endpoints (built-in fallbacks)
 * These can be overridden by the config file
 * ============================================================ */

/* Facebook / Messenger defaults */
#define META_DEFAULT_OAUTH_AUTH_URL     "https://www.facebook.com/v18.0/dialog/oauth"
#define META_DEFAULT_OAUTH_TOKEN_URL    "https://graph.facebook.com/v18.0/oauth/access_token"
#define META_DEFAULT_GRAPH_API_BASE     "https://graph.facebook.com/v18.0"
#define META_DEFAULT_MQTT_ENDPOINT      "wss://edge-chat.facebook.com/chat"
#define META_DEFAULT_MQTT_ORIGIN        "https://www.facebook.com"

/* Instagram defaults */
#define META_DEFAULT_IG_API_BASE        "https://i.instagram.com/api/v1"
#define META_DEFAULT_IG_GRAPHQL_API     "https://www.instagram.com/api/graphql"
#define META_DEFAULT_IG_REALTIME_URL    "wss://edge-chat.instagram.com/chat"
#define META_DEFAULT_IG_UPLOAD_URL      "https://i.instagram.com/rupload_igphoto/"

/* API version info */
#define META_DEFAULT_GRAPH_API_VERSION  "v18.0"
#define META_DEFAULT_IG_APP_VERSION     "275.0.0.27.98"
#define META_DEFAULT_IG_VERSION_CODE    "458229237"

/* ============================================================
 * Configuration Structure
 * ============================================================ */

/**
 * Messenger endpoint configuration
 */
typedef struct _MetaMessengerConfig {
    gchar *oauth_auth_url;
    gchar *oauth_token_url;
    gchar *graph_api_base;
    gchar *mqtt_endpoint;
    gchar *mqtt_origin;
    gchar *graph_api_version;
    
    /* OAuth settings */
    gchar *oauth_client_id;
    gchar *oauth_redirect_uri;
    gchar *oauth_scope;
    
    /* Rate limits */
    guint rate_limit_calls;
    guint rate_limit_window;
    guint min_request_interval_ms;
} MetaMessengerConfig;

/**
 * Instagram endpoint configuration
 */
typedef struct _MetaInstagramConfig {
    gchar *api_base;
    gchar *graphql_api;
    gchar *realtime_url;
    gchar *upload_url;
    
    /* App simulation */
    gchar *app_version;
    gchar *version_code;
    gchar *sig_key_version;
    gchar *user_agent;
    
    /* Device simulation */
    gchar *device_manufacturer;
    gchar *device_model;
    gchar *android_version;
    gchar *android_release;
    
    /* Rate limits (Instagram is stricter) */
    guint rate_limit_calls;
    guint rate_limit_window;
    guint min_request_interval_ms;
    
    /* Required headers */
    gchar *x_ig_capabilities;
    gchar *x_ig_connection_type;
    gchar *x_ig_app_id;
} MetaInstagramConfig;

/**
 * WebSocket/MQTT configuration
 */
typedef struct _MetaWebSocketConfig {
    guint connect_timeout;
    guint ping_interval;
    guint pong_timeout;
    guint reconnect_delay;
    guint max_reconnect_delay;
    guint max_reconnect_attempts;
    
    /* MQTT topics */
    gchar *topic_messages;
    gchar *topic_message_sync;
    gchar *topic_typing;
    gchar *topic_presence;
    gchar *topic_read_receipts;
    gchar *topic_thread_updates;
    
    /* Instagram topics */
    gchar *ig_topic_direct;
    gchar *ig_topic_message_sync;
    gchar *ig_topic_realtime;
} MetaWebSocketConfig;

/**
 * Security configuration
 */
typedef struct _MetaSecurityConfig {
    gboolean warn_plaintext_storage;
    gboolean obfuscate_tokens;
    guint max_token_age;
    guint max_failed_logins;
    guint login_lockout_duration;
    
    /* TLS settings */
    gboolean require_tls_1_2;
    gboolean verify_certificates;
    
    /* Rate limit response */
    guint initial_backoff;
    guint max_backoff;
    guint backoff_multiplier;
} MetaSecurityConfig;

/**
 * Feature flags (for gradual rollout or disabling broken features)
 */
typedef struct _MetaFeatureFlags {
    gboolean messenger_enabled;
    gboolean instagram_enabled;
    gboolean presence_enabled;
    gboolean typing_enabled;
    gboolean read_receipts_enabled;
    gboolean reactions_enabled;
    gboolean attachments_enabled;
    gboolean group_chats_enabled;
    
    /* Instagram-specific */
    gboolean ig_pending_inbox_enabled;
    gboolean ig_disappearing_enabled;
    gboolean ig_voice_enabled;
} MetaFeatureFlags;

/**
 * Main configuration structure
 */
typedef struct _MetaConfig {
    gint version;
    gint64 last_updated;
    gchar *update_url;
    
    MetaMessengerConfig messenger;
    MetaInstagramConfig instagram;
    MetaWebSocketConfig websocket;
    MetaSecurityConfig security;
    MetaFeatureFlags features;
    
    /* Debug settings */
    gboolean debug_mode;
    gboolean log_api_calls;
    gboolean log_websocket;
    
    /* Config file path that was loaded */
    gchar *loaded_from;
} MetaConfig;

/* ============================================================
 * Global Configuration Access
 * ============================================================ */

/**
 * Get the global configuration instance
 * Loads configuration on first call
 * 
 * @return Global MetaConfig instance (do not free)
 */
MetaConfig *meta_config_get(void);

/**
 * Reload configuration from disk
 * Call this if config file may have changed
 * 
 * @return TRUE if reload succeeded
 */
gboolean meta_config_reload(void);

/**
 * Check for configuration updates (optional)
 * Downloads latest config from update URL
 * 
 * @param callback Function to call with result
 * @param user_data User data for callback
 */
void meta_config_check_update_async(GCallback callback, gpointer user_data);

/**
 * Free the global configuration
 * Call on plugin unload
 */
void meta_config_free(void);

/* ============================================================
 * Configuration Loading
 * ============================================================ */

/**
 * Load configuration from a file
 * 
 * @param filepath Path to config file
 * @return Loaded config or NULL on error
 */
MetaConfig *meta_config_load_file(const char *filepath);

/**
 * Load configuration from JSON string
 * 
 * @param json JSON string
 * @return Loaded config or NULL on error
 */
MetaConfig *meta_config_load_json(const char *json);

/**
 * Create default configuration
 * 
 * @return Config with built-in defaults
 */
MetaConfig *meta_config_create_default(void);

/**
 * Save configuration to file
 * 
 * @param config Config to save
 * @param filepath Path to save to
 * @return TRUE if save succeeded
 */
gboolean meta_config_save_file(MetaConfig *config, const char *filepath);

/**
 * Export configuration to JSON string
 * 
 * @param config Config to export
 * @return JSON string (caller must free)
 */
gchar *meta_config_to_json(MetaConfig *config);

/* ============================================================
 * Configuration Helpers
 * ============================================================ */

/**
 * Get user config file path
 * 
 * @return Path to user config file (caller must free)
 */
gchar *meta_config_get_user_path(void);

/**
 * Get system config file path
 * 
 * @return Path to system config file (caller must free)
 */
gchar *meta_config_get_system_path(void);

/**
 * Merge two configs (overlay over base)
 * 
 * @param base Base configuration
 * @param overlay Configuration to overlay
 * @return Merged configuration (caller must free)
 */
MetaConfig *meta_config_merge(MetaConfig *base, MetaConfig *overlay);

/**
 * Validate configuration
 * 
 * @param config Config to validate
 * @param error Output: error message if invalid
 * @return TRUE if valid
 */
gboolean meta_config_validate(MetaConfig *config, gchar **error);

/* ============================================================
 * Convenience Getters
 * ============================================================ */

/* Messenger endpoints */
const gchar *meta_config_get_oauth_auth_url(void);
const gchar *meta_config_get_oauth_token_url(void);
const gchar *meta_config_get_graph_api_base(void);
const gchar *meta_config_get_mqtt_endpoint(void);
const gchar *meta_config_get_mqtt_origin(void);

/* Instagram endpoints */
const gchar *meta_config_get_ig_api_base(void);
const gchar *meta_config_get_ig_graphql_api(void);
const gchar *meta_config_get_ig_realtime_url(void);
const gchar *meta_config_get_ig_upload_url(void);
const gchar *meta_config_get_ig_user_agent(void);

/* WebSocket settings */
guint meta_config_get_ws_connect_timeout(void);
guint meta_config_get_ws_ping_interval(void);
guint meta_config_get_ws_reconnect_delay(void);

/* Feature checks */
gboolean meta_config_is_messenger_enabled(void);
gboolean meta_config_is_instagram_enabled(void);
gboolean meta_config_is_feature_enabled(const char *feature_name);

/* Rate limits */
guint meta_config_get_rate_limit_calls(gboolean is_instagram);
guint meta_config_get_rate_limit_window(gboolean is_instagram);
guint meta_config_get_min_request_interval(gboolean is_instagram);

/* ============================================================
 * Dynamic Endpoint Building
 * ============================================================ */

/**
 * Build a Graph API URL with current version
 * 
 * @param endpoint API endpoint (e.g., "/me/messages")
 * @return Full URL (caller must free)
 */
gchar *meta_config_build_graph_url(const char *endpoint);

/**
 * Build an Instagram API URL
 * 
 * @param endpoint API endpoint (e.g., "/direct_v2/inbox/")
 * @return Full URL (caller must free)
 */
gchar *meta_config_build_ig_url(const char *endpoint);

/**
 * Get Instagram headers as hash table
 * 
 * @return Headers (caller must free with g_hash_table_destroy)
 */
GHashTable *meta_config_get_ig_headers(void);

/* ============================================================
 * Memory Management
 * ============================================================ */

/**
 * Free a MetaConfig structure
 * 
 * @param config Config to free
 */
void meta_config_destroy(MetaConfig *config);

/**
 * Deep copy a MetaConfig structure
 * 
 * @param config Config to copy
 * @return New config copy (caller must free)
 */
MetaConfig *meta_config_copy(MetaConfig *config);

#endif /* META_CONFIG_H */