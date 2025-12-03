/**
 * instagram.h
 * 
 * Instagram DM service module for libpurple-meta
 * Handles Instagram-specific API calls and Direct Message handling
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef INSTAGRAM_H
#define INSTAGRAM_H

#include <glib.h>
#include <purple.h>
#include <json-glib/json-glib.h>
#include "../prpl-meta.h"

/* Instagram API endpoints */
#define INSTAGRAM_API_BASE          "https://i.instagram.com/api/v1"
#define INSTAGRAM_GRAPHQL_API       "https://www.instagram.com/api/graphql"
#define INSTAGRAM_DIRECT_API        INSTAGRAM_API_BASE "/direct_v2"
#define INSTAGRAM_INBOX_API         INSTAGRAM_DIRECT_API "/inbox/"
#define INSTAGRAM_THREADS_API       INSTAGRAM_DIRECT_API "/threads/"
#define INSTAGRAM_SEND_API          INSTAGRAM_DIRECT_API "/threads/broadcast/text/"
#define INSTAGRAM_UPLOAD_API        "https://i.instagram.com/rupload_igphoto/"

/* Instagram-specific message types */
typedef enum {
    INSTAGRAM_MSG_TEXT = 0,
    INSTAGRAM_MSG_LINK,
    INSTAGRAM_MSG_MEDIA_SHARE,
    INSTAGRAM_MSG_REEL_SHARE,
    INSTAGRAM_MSG_STORY_SHARE,
    INSTAGRAM_MSG_VOICE_MEDIA,
    INSTAGRAM_MSG_ANIMATED_MEDIA,    /* GIFs */
    INSTAGRAM_MSG_CLIP,              /* Reels */
    INSTAGRAM_MSG_FELIX_SHARE,       /* IGTV */
    INSTAGRAM_MSG_RAVEN_MEDIA,       /* Disappearing media */
    INSTAGRAM_MSG_PROFILE,
    INSTAGRAM_MSG_LOCATION,
    INSTAGRAM_MSG_HASHTAG,
    INSTAGRAM_MSG_LIKE,              /* Heart reaction */
    INSTAGRAM_MSG_REACTION
} InstagramMessageType;

/* Thread types */
typedef enum {
    INSTAGRAM_THREAD_PRIVATE = 0,
    INSTAGRAM_THREAD_GROUP,
    INSTAGRAM_THREAD_PENDING         /* Message request */
} InstagramThreadType;

/* Instagram-specific data */
typedef struct _InstagramData {
    /* Session info */
    gchar *session_id;
    gchar *csrf_token;
    gchar *device_id;
    gchar *uuid;
    gchar *phone_id;
    gchar *advertising_id;
    
    /* User info */
    gchar *user_id;
    gchar *username;
    gchar *full_name;
    gchar *profile_pic_url;
    
    /* Sync state */
    gchar *seq_id;                   /* Sequence ID for inbox sync */
    gchar *snapshot_at_ms;           /* Snapshot timestamp */
    gchar *cursor;                   /* Pagination cursor */
    gint64 last_sync;
    
    /* Thread cache */
    GHashTable *pending_threads;     /* Message requests */
    
    /* Rate limiting */
    gint64 last_api_call;
    guint api_call_count;
    
    /* Realtime subscription */
    gboolean realtime_connected;
    gchar *mqtt_client_id;
} InstagramData;

/* ============================================================
 * Service Lifecycle
 * ============================================================ */

/**
 * Create a new Instagram service instance
 * 
 * @return New MetaService for Instagram
 */
MetaService *instagram_service_new(void);

/**
 * Free an Instagram service instance
 * 
 * @param service The service to free
 */
void instagram_service_free(MetaService *service);

/**
 * Initialize Instagram-specific data for an account
 * 
 * @param account The Meta account
 * @return TRUE if initialization succeeded
 */
gboolean instagram_init(MetaAccount *account);

/**
 * Cleanup Instagram-specific data
 * 
 * @param account The Meta account
 */
void instagram_cleanup(MetaAccount *account);

/* ============================================================
 * Connection
 * ============================================================ */

/**
 * Connect to Instagram service
 * 
 * @param account The Meta account
 * @return TRUE if connection initiated
 */
gboolean instagram_connect(MetaAccount *account);

/**
 * Disconnect from Instagram service
 * 
 * @param account The Meta account
 */
void instagram_disconnect(MetaAccount *account);

/**
 * Reconnect to Instagram service
 * 
 * @param account The Meta account
 * @return TRUE if reconnection initiated
 */
gboolean instagram_reconnect(MetaAccount *account);

/* ============================================================
 * Messaging
 * ============================================================ */

/**
 * Send a message via Instagram DM
 * 
 * @param account The Meta account
 * @param to Recipient user ID or thread ID
 * @param message Message text
 * @param type Message type
 * @return TRUE if message was sent
 */
gboolean instagram_send_message(MetaAccount *account, const char *to,
                                 const char *message, MetaMessageType type);

/**
 * Send typing indicator (Instagram calls this "activity")
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param typing TRUE if typing, FALSE if stopped
 * @return TRUE if indicator was sent
 */
gboolean instagram_send_typing(MetaAccount *account, const char *thread_id,
                                gboolean typing);

/**
 * Mark a thread as seen
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param item_id Last seen item ID
 * @return TRUE if mark succeeded
 */
gboolean instagram_mark_seen(MetaAccount *account, const char *thread_id,
                              const char *item_id);

/**
 * Send a heart reaction (like)
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param item_id Item to react to
 * @return TRUE if reaction was sent
 */
gboolean instagram_send_like(MetaAccount *account, const char *thread_id,
                              const char *item_id);

/**
 * Send an emoji reaction
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param item_id Item to react to
 * @param emoji Reaction emoji
 * @return TRUE if reaction was sent
 */
gboolean instagram_send_reaction(MetaAccount *account, const char *thread_id,
                                  const char *item_id, const char *emoji);

/**
 * Unsend (delete) a message
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param item_id Item to unsend
 * @return TRUE if unsend succeeded
 */
gboolean instagram_unsend_message(MetaAccount *account, const char *thread_id,
                                   const char *item_id);

/* ============================================================
 * Media
 * ============================================================ */

/**
 * Send a photo
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param filepath Path to image file
 * @return TRUE if upload initiated
 */
gboolean instagram_send_photo(MetaAccount *account, const char *thread_id,
                               const char *filepath);

/**
 * Send voice message
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param filepath Path to audio file
 * @return TRUE if upload initiated
 */
gboolean instagram_send_voice(MetaAccount *account, const char *thread_id,
                               const char *filepath);

/**
 * Send a link
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param url URL to share
 * @param text Optional text with the link
 * @return TRUE if link was sent
 */
gboolean instagram_send_link(MetaAccount *account, const char *thread_id,
                              const char *url, const char *text);

/**
 * Share a post to DM
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param media_id Media ID of post to share
 * @return TRUE if share was sent
 */
gboolean instagram_share_post(MetaAccount *account, const char *thread_id,
                               const char *media_id);

/**
 * Download media from a message
 * 
 * @param account The Meta account
 * @param media_url URL of the media
 * @return Local path to downloaded file (caller must free)
 */
gchar *instagram_download_media(MetaAccount *account, const char *media_url);

/* ============================================================
 * Thread Management
 * ============================================================ */

/**
 * Get inbox (list of threads)
 * 
 * @param account The Meta account
 * @return List of MetaThread* (caller must free)
 */
GList *instagram_get_inbox(MetaAccount *account);

/**
 * Get pending message requests
 * 
 * @param account The Meta account
 * @return List of MetaThread* (caller must free)
 */
GList *instagram_get_pending_inbox(MetaAccount *account);

/**
 * Get a specific thread by ID
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @return MetaThread* or NULL if not found
 */
MetaThread *instagram_get_thread(MetaAccount *account, const char *thread_id);

/**
 * Get messages from a thread
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param cursor Pagination cursor (or NULL for latest)
 * @return List of MetaMessage* (caller must free)
 */
GList *instagram_get_thread_items(MetaAccount *account, const char *thread_id,
                                   const char *cursor);

/**
 * Create a new thread with a user
 * 
 * @param account The Meta account
 * @param user_ids List of user IDs
 * @return Thread ID of new thread (caller must free)
 */
gchar *instagram_create_thread(MetaAccount *account, GList *user_ids);

/**
 * Create a group thread
 * 
 * @param account The Meta account
 * @param user_ids List of user IDs
 * @param title Group title
 * @return Thread ID of new group (caller must free)
 */
gchar *instagram_create_group(MetaAccount *account, GList *user_ids,
                               const char *title);

/**
 * Leave a group thread
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @return TRUE if left successfully
 */
gboolean instagram_leave_thread(MetaAccount *account, const char *thread_id);

/**
 * Add users to a group thread
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param user_ids List of user IDs to add
 * @return TRUE if users were added
 */
gboolean instagram_add_users_to_thread(MetaAccount *account,
                                        const char *thread_id,
                                        GList *user_ids);

/**
 * Mute a thread
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param mute TRUE to mute, FALSE to unmute
 * @return TRUE if mute state changed
 */
gboolean instagram_mute_thread(MetaAccount *account, const char *thread_id,
                                gboolean mute);

/**
 * Approve a pending message request
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @return TRUE if approved
 */
gboolean instagram_approve_thread(MetaAccount *account, const char *thread_id);

/**
 * Decline/delete a pending message request
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @return TRUE if declined
 */
gboolean instagram_decline_thread(MetaAccount *account, const char *thread_id);

/* ============================================================
 * User Operations
 * ============================================================ */

/**
 * Get user info by user ID
 * 
 * @param account The Meta account
 * @param user_id User ID
 * @return MetaUser* or NULL if not found
 */
MetaUser *instagram_get_user_info(MetaAccount *account, const char *user_id);

/**
 * Get user info by username
 * 
 * @param account The Meta account
 * @param username Username
 * @return MetaUser* or NULL if not found
 */
MetaUser *instagram_get_user_by_username(MetaAccount *account,
                                          const char *username);

/**
 * Search for users
 * 
 * @param account The Meta account
 * @param query Search query
 * @return List of MetaUser* (caller must free)
 */
GList *instagram_search_users(MetaAccount *account, const char *query);

/* ============================================================
 * Presence (Instagram doesn't have traditional presence)
 * ============================================================ */

/**
 * Set presence/activity status
 * Note: Instagram has limited presence support
 * 
 * @param account The Meta account
 * @param status Status to set
 */
void instagram_set_presence(MetaAccount *account, PurpleStatusPrimitive status);

/* ============================================================
 * API Helpers
 * ============================================================ */

/**
 * Generate required headers for Instagram API requests
 * 
 * @param data Instagram data
 * @return GHashTable of headers (caller must free)
 */
GHashTable *instagram_get_headers(InstagramData *data);

/**
 * Generate device info for API requests
 * 
 * @param data Instagram data
 * @return JSON string of device info (caller must free)
 */
gchar *instagram_get_device_info(InstagramData *data);

/**
 * Sign a request payload (Instagram uses signed requests)
 * 
 * @param payload JSON payload to sign
 * @return Signed payload string (caller must free)
 */
gchar *instagram_sign_request(const char *payload);

/**
 * Generate UUID for Instagram
 * 
 * @return UUID string (caller must free)
 */
gchar *instagram_generate_uuid(void);

/**
 * Generate device ID for Instagram
 * 
 * @param seed Seed string (usually username)
 * @return Device ID string (caller must free)
 */
gchar *instagram_generate_device_id(const char *seed);

/**
 * Parse Instagram API response
 * 
 * @param response Response data
 * @param len Response length
 * @param error Output: error message if failed
 * @return JsonObject* or NULL on error (caller must free)
 */
JsonObject *instagram_parse_response(const char *response, gsize len,
                                      gchar **error);

/**
 * Check if rate limited
 * 
 * @param data Instagram data
 * @return TRUE if should wait before making API calls
 */
gboolean instagram_is_rate_limited(InstagramData *data);

/**
 * Record an API call for rate limiting
 * 
 * @param data Instagram data
 */
void instagram_record_api_call(InstagramData *data);

/* ============================================================
 * Parsing Helpers
 * ============================================================ */

/**
 * Parse inbox response into threads
 * 
 * @param json_str JSON response
 * @return List of MetaThread* (caller must free)
 */
GList *instagram_parse_inbox(const char *json_str);

/**
 * Parse thread items (messages)
 * 
 * @param json_str JSON response
 * @return List of MetaMessage* (caller must free)
 */
GList *instagram_parse_thread_items(const char *json_str);

/**
 * Parse a single thread from JSON
 * 
 * @param thread_obj JSON object for thread
 * @return MetaThread* (caller must free)
 */
MetaThread *instagram_parse_thread(JsonObject *thread_obj);

/**
 * Parse a single message item from JSON
 * 
 * @param item_obj JSON object for item
 * @return MetaMessage* (caller must free)
 */
MetaMessage *instagram_parse_item(JsonObject *item_obj);

/**
 * Parse user from JSON
 * 
 * @param user_obj JSON object for user
 * @return MetaUser* (caller must free)
 */
MetaUser *instagram_parse_user(JsonObject *user_obj);

#endif /* INSTAGRAM_H */