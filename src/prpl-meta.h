/**
 * prpl-meta.h
 * 
 * Main header file for libpurple-meta plugin
 * Unified Meta (Facebook Messenger + Instagram DM) protocol plugin
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef PRPL_META_H
#define PRPL_META_H

#include <glib.h>
#include <purple.h>

/* Plugin identification */
#define META_PLUGIN_ID      "prpl-meta"
#define META_PLUGIN_NAME    "Meta (Messenger + Instagram)"
#define META_PLUGIN_VERSION "0.1.0"
#define META_PLUGIN_AUTHOR  "libpurple-meta contributors"
#define META_PLUGIN_WEBSITE "https://github.com/libpurple-meta"

/* Service modes */
typedef enum {
    META_SERVICE_MESSENGER = 0,
    META_SERVICE_INSTAGRAM = 1,
    META_SERVICE_UNIFIED   = 2   /* Both services in one account */
} MetaServiceMode;

/* Connection states */
typedef enum {
    META_STATE_DISCONNECTED = 0,
    META_STATE_CONNECTING,
    META_STATE_AUTHENTICATING,
    META_STATE_CONNECTED,
    META_STATE_RECONNECTING,
    META_STATE_ERROR
} MetaConnectionState;

/* Message types */
typedef enum {
    META_MSG_TEXT = 0,
    META_MSG_IMAGE,
    META_MSG_VIDEO,
    META_MSG_AUDIO,
    META_MSG_FILE,
    META_MSG_STICKER,
    META_MSG_REACTION,
    META_MSG_TYPING,
    META_MSG_READ_RECEIPT,
    META_MSG_PRESENCE
} MetaMessageType;

/* Forward declarations */
typedef struct _MetaAccount MetaAccount;
typedef struct _MetaService MetaService;
typedef struct _MetaMessage MetaMessage;
typedef struct _MetaThread  MetaThread;
typedef struct _MetaUser    MetaUser;

/**
 * MetaService - Transport abstraction layer
 * 
 * This allows unified handling of Messenger and Instagram
 * with service-specific implementations.
 */
struct _MetaService {
    const char *id;             /* "messenger" or "instagram" */
    const char *display_name;   /* Human-readable name */
    
    /* Connection lifecycle */
    gboolean (*connect)(MetaAccount *account);
    void (*disconnect)(MetaAccount *account);
    gboolean (*reconnect)(MetaAccount *account);
    
    /* Messaging */
    gboolean (*send_message)(MetaAccount *account, const char *to, 
                             const char *message, MetaMessageType type);
    gboolean (*send_typing)(MetaAccount *account, const char *to, 
                            gboolean typing);
    gboolean (*mark_read)(MetaAccount *account, const char *thread_id,
                          const char *message_id);
    
    /* Thread management */
    GList *(*get_threads)(MetaAccount *account);
    MetaThread *(*get_thread)(MetaAccount *account, const char *thread_id);
    GList *(*get_thread_messages)(MetaAccount *account, const char *thread_id,
                                   int limit, const char *before_cursor);
    
    /* Media handling */
    gboolean (*upload_media)(MetaAccount *account, const char *thread_id,
                             const char *filepath, MetaMessageType type);
    gchar *(*download_media)(MetaAccount *account, const char *media_url);
    
    /* Presence (Messenger only typically) */
    void (*set_presence)(MetaAccount *account, PurpleStatusPrimitive status);
    
    /* Private data for the service */
    gpointer priv;
};

/**
 * MetaAccount - Per-account state
 */
struct _MetaAccount {
    PurpleAccount *pa;          /* libpurple account */
    PurpleConnection *pc;       /* libpurple connection */
    
    MetaServiceMode mode;       /* Which service(s) to use */
    MetaConnectionState state;  /* Current connection state */
    
    /* Authentication tokens */
    gchar *access_token;        /* OAuth access token */
    gchar *session_cookies;     /* Session cookies JSON */
    gint64 token_expiry;        /* Token expiration timestamp */
    gchar *user_id;             /* Meta user ID */
    gchar *device_id;           /* Device identifier for API */
    
    /* Service instances */
    MetaService *messenger;     /* Messenger service (or NULL) */
    MetaService *instagram;     /* Instagram service (or NULL) */
    MetaService *active;        /* Currently active service */
    
    /* WebSocket connection state */
    gpointer ws_connection;     /* MetaWebSocket* */
    guint ws_keepalive_handle;  /* GLib timeout for keepalive */
    
    /* Message queue for offline/reconnect */
    GQueue *pending_messages;
    
    /* Thread cache */
    GHashTable *threads;        /* thread_id -> MetaThread* */
    GHashTable *users;          /* user_id -> MetaUser* */
    
    /* Sync state */
    gint64 last_sync_timestamp;
    gchar *sync_cursor;
    
    /* Rate limiting */
    gint64 last_request_time;
    guint request_count;
};

/**
 * MetaMessage - Unified message structure
 */
struct _MetaMessage {
    gchar *id;                  /* Message ID */
    gchar *thread_id;           /* Thread/conversation ID */
    gchar *sender_id;           /* Sender user ID */
    gchar *text;                /* Message text (for text messages) */
    MetaMessageType type;       /* Message type */
    gint64 timestamp;           /* Unix timestamp in milliseconds */
    gboolean is_outgoing;       /* TRUE if sent by us */
    gboolean is_read;           /* Read status */
    
    /* For media messages */
    gchar *media_url;           /* URL to media */
    gchar *media_preview_url;   /* Thumbnail URL */
    gchar *media_mime_type;     /* MIME type */
    gsize media_size;           /* File size in bytes */
    
    /* For reactions */
    gchar *reaction_emoji;      /* Reaction emoji */
    gchar *target_message_id;   /* Message being reacted to */
    
    /* Reply context */
    gchar *reply_to_id;         /* ID of message being replied to */
    gchar *reply_preview;       /* Preview text of replied message */
};

/**
 * MetaThread - Conversation/thread structure
 */
struct _MetaThread {
    gchar *id;                  /* Thread ID */
    gchar *name;                /* Thread name (for groups) */
    gboolean is_group;          /* TRUE for group chats */
    GList *participants;        /* List of MetaUser* */
    gint64 last_activity;       /* Last activity timestamp */
    gchar *last_message_preview;/* Preview of last message */
    guint unread_count;         /* Number of unread messages */
    
    /* For Instagram */
    gboolean is_pending;        /* Pending message request */
    
    /* Cached messages */
    GList *messages;            /* Recent MetaMessage* list */
    gchar *messages_cursor;     /* Pagination cursor */
};

/**
 * MetaUser - User/contact structure
 */
struct _MetaUser {
    gchar *id;                  /* User ID */
    gchar *username;            /* Username (Instagram) or vanity URL */
    gchar *display_name;        /* Full display name */
    gchar *avatar_url;          /* Profile picture URL */
    gboolean is_verified;       /* Verified badge */
    
    /* Presence (Messenger) */
    PurpleStatusPrimitive presence;
    gint64 last_active;         /* Last active timestamp */
};

/* ============================================================
 * Public API
 * ============================================================ */

/* Plugin lifecycle */
gboolean meta_plugin_load(PurplePlugin *plugin);
gboolean meta_plugin_unload(PurplePlugin *plugin);

/* Account management */
MetaAccount *meta_account_new(PurpleAccount *pa);
void meta_account_free(MetaAccount *account);
MetaAccount *meta_account_get(PurpleAccount *pa);

/* Connection */
void meta_login(PurpleAccount *account);
void meta_logout(PurpleConnection *gc);
void meta_close(PurpleConnection *gc);

/* Messaging */
#if PURPLE_VERSION == 2
int meta_send_im(PurpleConnection *gc, const char *who, const char *message, PurpleMessageFlags flags);
unsigned int meta_send_typing(PurpleConnection *gc, const char *name, 
                               PurpleTypingState state);
#else
int meta_send_im(PurpleConnection *gc, PurpleMessage *msg);
unsigned int meta_send_typing(PurpleConnection *gc, const char *name, 
                               PurpleIMTypingState state);
#endif

/* Buddy list */
void meta_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, 
                    PurpleGroup *group, const char *message);
void meta_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, 
                       PurpleGroup *group);

/* Status */
void meta_set_status(PurpleAccount *account, PurpleStatus *status);

/* Chat (group) operations */
GList *meta_chat_info(PurpleConnection *gc);
GHashTable *meta_chat_info_defaults(PurpleConnection *gc, const char *room);
void meta_join_chat(PurpleConnection *gc, GHashTable *components);
void meta_chat_leave(PurpleConnection *gc, int id);
#if PURPLE_VERSION == 2
int meta_chat_send(PurpleConnection *gc, int id, const char *message, PurpleMessageFlags flags);
#else
int meta_chat_send(PurpleConnection *gc, int id, PurpleMessage *msg);
#endif

/* Utility macros */
#define META_ACCOUNT(pa) (meta_account_get(pa))
#define META_GC_ACCOUNT(gc) (META_ACCOUNT(purple_connection_get_account(gc)))

/* Debug logging */
#define meta_debug(fmt, ...) \
    purple_debug_info(META_PLUGIN_ID, fmt "\n", ##__VA_ARGS__)
#define meta_warning(fmt, ...) \
    purple_debug_warning(META_PLUGIN_ID, fmt "\n", ##__VA_ARGS__)
#define meta_error(fmt, ...) \
    purple_debug_error(META_PLUGIN_ID, fmt "\n", ##__VA_ARGS__)

#endif /* PRPL_META_H */