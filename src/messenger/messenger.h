/**
 * messenger.h
 * 
 * Facebook Messenger service module for libpurple-meta
 * Handles Messenger-specific API calls and message handling
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef MESSENGER_H
#define MESSENGER_H

#include <glib.h>
#include <purple.h>
#include "../prpl-meta.h"

/* Messenger API endpoints */
#define MESSENGER_GRAPH_API         "https://graph.facebook.com/v18.0"
#define MESSENGER_SEND_API          MESSENGER_GRAPH_API "/me/messages"
#define MESSENGER_PROFILE_API       MESSENGER_GRAPH_API "/me"
#define MESSENGER_CONVERSATIONS_API MESSENGER_GRAPH_API "/me/conversations"

/* Message attachment types */
typedef enum {
    MESSENGER_ATTACH_IMAGE = 0,
    MESSENGER_ATTACH_VIDEO,
    MESSENGER_ATTACH_AUDIO,
    MESSENGER_ATTACH_FILE,
    MESSENGER_ATTACH_TEMPLATE,
    MESSENGER_ATTACH_STICKER
} MessengerAttachmentType;

/* Messenger-specific data */
typedef struct _MessengerData {
    /* Page access token (for business/page messaging) */
    gchar *page_access_token;
    gchar *page_id;
    
    /* User messaging token */
    gchar *user_access_token;
    
    /* Current user profile */
    gchar *user_name;
    gchar *profile_pic_url;
    
    /* Thread sync state */
    gchar *thread_sync_cursor;
    gint64 last_thread_sync;
    
    /* Rate limiting */
    gint64 last_api_call;
    guint api_call_count;
    
    /* Presence tracking */
    GHashTable *presence_cache;     /* user_id -> last_active timestamp */
    guint presence_poll_handle;
} MessengerData;

/* ============================================================
 * Service Lifecycle
 * ============================================================ */

/**
 * Create a new Messenger service instance
 * 
 * @return New MetaService for Messenger
 */
MetaService *messenger_service_new(void);

/**
 * Free a Messenger service instance
 * 
 * @param service The service to free
 */
void messenger_service_free(MetaService *service);

/**
 * Initialize Messenger-specific data for an account
 * 
 * @param account The Meta account
 * @return TRUE if initialization succeeded
 */
gboolean messenger_init(MetaAccount *account);

/**
 * Cleanup Messenger-specific data
 * 
 * @param account The Meta account
 */
void messenger_cleanup(MetaAccount *account);

/* ============================================================
 * Connection
 * ============================================================ */

/**
 * Connect to Messenger service
 * 
 * @param account The Meta account
 * @return TRUE if connection initiated
 */
gboolean messenger_connect(MetaAccount *account);

/**
 * Disconnect from Messenger service
 * 
 * @param account The Meta account
 */
void messenger_disconnect(MetaAccount *account);

/**
 * Reconnect to Messenger service
 * 
 * @param account The Meta account
 * @return TRUE if reconnection initiated
 */
gboolean messenger_reconnect(MetaAccount *account);

/* ============================================================
 * Messaging
 * ============================================================ */

/**
 * Send a message via Messenger
 * 
 * @param account The Meta account
 * @param to Recipient user ID or thread ID
 * @param message Message text
 * @param type Message type
 * @return TRUE if message was sent
 */
gboolean messenger_send_message(MetaAccount *account, const char *to,
                                 const char *message, MetaMessageType type);

/**
 * Send typing indicator
 * 
 * @param account The Meta account
 * @param to Recipient user ID
 * @param typing TRUE if typing, FALSE if stopped
 * @return TRUE if indicator was sent
 */
gboolean messenger_send_typing(MetaAccount *account, const char *to,
                                gboolean typing);

/**
 * Mark a message as read
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param message_id Message ID to mark as read
 * @return TRUE if mark succeeded
 */
gboolean messenger_mark_read(MetaAccount *account, const char *thread_id,
                              const char *message_id);

/**
 * Send a reaction to a message
 * 
 * @param account The Meta account
 * @param message_id Message to react to
 * @param emoji Reaction emoji (or NULL to remove)
 * @return TRUE if reaction was sent
 */
gboolean messenger_send_reaction(MetaAccount *account, const char *message_id,
                                  const char *emoji);

/* ============================================================
 * Attachments
 * ============================================================ */

/**
 * Send an attachment (image, video, file, etc.)
 * 
 * @param account The Meta account
 * @param to Recipient user ID or thread ID
 * @param filepath Local path to the file
 * @param type Attachment type
 * @return TRUE if upload initiated
 */
gboolean messenger_send_attachment(MetaAccount *account, const char *to,
                                    const char *filepath,
                                    MessengerAttachmentType type);

/**
 * Download an attachment
 * 
 * @param account The Meta account
 * @param attachment_url URL of the attachment
 * @return Local path to downloaded file (caller must free)
 */
gchar *messenger_download_attachment(MetaAccount *account,
                                      const char *attachment_url);

/* ============================================================
 * Thread Management
 * ============================================================ */

/**
 * Get list of conversation threads
 * 
 * @param account The Meta account
 * @return List of MetaThread* (caller must free)
 */
GList *messenger_get_threads(MetaAccount *account);

/**
 * Get a specific thread by ID
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @return MetaThread* or NULL if not found
 */
MetaThread *messenger_get_thread(MetaAccount *account, const char *thread_id);

/**
 * Get messages from a thread
 * 
 * @param account The Meta account
 * @param thread_id Thread ID
 * @param limit Maximum messages to fetch
 * @param before_cursor Pagination cursor (or NULL for latest)
 * @return List of MetaMessage* (caller must free)
 */
GList *messenger_get_thread_messages(MetaAccount *account,
                                      const char *thread_id,
                                      int limit,
                                      const char *before_cursor);

/**
 * Create a new group thread
 * 
 * @param account The Meta account
 * @param name Group name
 * @param participants List of user IDs to add
 * @return Thread ID of new group (caller must free)
 */
gchar *messenger_create_group(MetaAccount *account, const char *name,
                               GList *participants);

/**
 * Add a participant to a group thread
 * 
 * @param account The Meta account
 * @param thread_id Group thread ID
 * @param user_id User to add
 * @return TRUE if user was added
 */
gboolean messenger_add_participant(MetaAccount *account, const char *thread_id,
                                    const char *user_id);

/**
 * Remove a participant from a group thread
 * 
 * @param account The Meta account
 * @param thread_id Group thread ID
 * @param user_id User to remove
 * @return TRUE if user was removed
 */
gboolean messenger_remove_participant(MetaAccount *account,
                                       const char *thread_id,
                                       const char *user_id);

/* ============================================================
 * Presence
 * ============================================================ */

/**
 * Set user presence status
 * 
 * @param account The Meta account
 * @param status Status to set
 */
void messenger_set_presence(MetaAccount *account, PurpleStatusPrimitive status);

/**
 * Get presence for a user
 * 
 * @param account The Meta account
 * @param user_id User ID to check
 * @return Presence status
 */
PurpleStatusPrimitive messenger_get_presence(MetaAccount *account,
                                              const char *user_id);

/**
 * Start presence polling
 * 
 * @param account The Meta account
 */
void messenger_start_presence_polling(MetaAccount *account);

/**
 * Stop presence polling
 * 
 * @param account The Meta account
 */
void messenger_stop_presence_polling(MetaAccount *account);

/* ============================================================
 * User Profiles
 * ============================================================ */

/**
 * Get user profile information
 * 
 * @param account The Meta account
 * @param user_id User ID to look up
 * @return MetaUser* or NULL if not found
 */
MetaUser *messenger_get_user_profile(MetaAccount *account, const char *user_id);

/**
 * Search for users by name
 * 
 * @param account The Meta account
 * @param query Search query
 * @return List of MetaUser* (caller must free)
 */
GList *messenger_search_users(MetaAccount *account, const char *query);

/* ============================================================
 * Utility Functions
 * ============================================================ */

/**
 * Parse a Messenger API response for messages
 * 
 * @param json_str JSON response string
 * @return List of MetaMessage* (caller must free)
 */
GList *messenger_parse_messages(const char *json_str);

/**
 * Parse a Messenger API response for threads
 * 
 * @param json_str JSON response string
 * @return List of MetaThread* (caller must free)
 */
GList *messenger_parse_threads(const char *json_str);

/**
 * Build a Graph API request URL
 * 
 * @param endpoint API endpoint
 * @param access_token Access token
 * @param params Additional query parameters (NULL-terminated key/value pairs)
 * @return Full URL (caller must free)
 */
gchar *messenger_build_api_url(const char *endpoint, const char *access_token,
                                ...);

/**
 * Check if rate limited
 * 
 * @param data Messenger data
 * @return TRUE if should wait before making API calls
 */
gboolean messenger_is_rate_limited(MessengerData *data);

/**
 * Record an API call for rate limiting
 * 
 * @param data Messenger data
 */
void messenger_record_api_call(MessengerData *data);

#endif /* MESSENGER_H */