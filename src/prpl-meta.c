/**
 * prpl-meta.c
 * 
 * Main plugin entry point for libpurple-meta
 * Unified Meta (Facebook Messenger + Instagram DM) protocol plugin for Pidgin
 * 
 * This started as a weekend project after purple-facebook died. Meta killed
 * XMPP years ago so we have to use their Graph API + WebSocket stuff now.
 * It's more complicated but at least it works with current Messenger/IG.
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#include "prpl-meta.h"
#include "common/meta-auth.h"
#include "common/meta-config.h"
#include "common/meta-security.h"
#include "common/meta-websocket.h"
#include "messenger/messenger.h"
#include "instagram/instagram.h"

#include <purple.h>
#include <glib.h>
#include <string.h>

/* Global account registry - maps PurpleAccount* to our MetaAccount* structs.
 * We need this because libpurple callbacks don't always give us easy access
 * to our internal state. */
static GHashTable *meta_accounts = NULL;

/* ============================================================
 * Account Management
 * ============================================================ */

MetaAccount *meta_account_new(PurpleAccount *pa)
{
    MetaAccount *account = g_new0(MetaAccount, 1);
    
    account->pa = pa;
    account->state = META_STATE_DISCONNECTED;
    account->mode = META_SERVICE_MESSENGER; /* Default to Messenger */
    
    /* Generate device ID if not stored */
    account->device_id = g_strdup(purple_account_get_string(pa, "device_id", NULL));
    if (!account->device_id) {
        account->device_id = g_uuid_string_random();
        purple_account_set_string(pa, "device_id", account->device_id);
    }
    
    /* Initialize data structures */
    account->pending_messages = g_queue_new();
    account->threads = g_hash_table_new_full(g_str_hash, g_str_equal, 
                                              g_free, NULL); /* TODO: free func */
    account->users = g_hash_table_new_full(g_str_hash, g_str_equal,
                                            g_free, NULL); /* TODO: free func */
    
    /* Initialize services */
    account->messenger = messenger_service_new();
    account->instagram = instagram_service_new();
    
    /* Store in registry */
    g_hash_table_insert(meta_accounts, pa, account);
    
    return account;
}

void meta_account_free(MetaAccount *account)
{
    if (!account) return;
    
    /* Remove from registry */
    g_hash_table_remove(meta_accounts, account->pa);
    
    /* Free auth tokens */
    g_free(account->access_token);
    g_free(account->session_cookies);
    g_free(account->user_id);
    g_free(account->device_id);
    g_free(account->sync_cursor);
    
    /* Free services */
    if (account->messenger) {
        messenger_service_free(account->messenger);
    }
    if (account->instagram) {
        instagram_service_free(account->instagram);
    }
    
    /* Free data structures */
    g_queue_free_full(account->pending_messages, g_free);
    g_hash_table_destroy(account->threads);
    g_hash_table_destroy(account->users);
    
    /* Cancel keepalive timer */
    if (account->ws_keepalive_handle) {
        g_source_remove(account->ws_keepalive_handle);
    }
    
    g_free(account);
}

MetaAccount *meta_account_get(PurpleAccount *pa)
{
    if (!meta_accounts) return NULL;
    return g_hash_table_lookup(meta_accounts, pa);
}

/* ============================================================
 * Protocol Actions (Menu items)
 * ============================================================ */

static void action_refresh_threads(PurpleProtocolAction *action)
{
    PurpleConnection *gc = action->connection;
    MetaAccount *account = META_GC_ACCOUNT(gc);
    
    if (!account || account->state != META_STATE_CONNECTED) {
        purple_notify_error(gc, "Meta", "Not connected", 
                           "You must be connected to refresh threads.",
                           NULL);
        return;
    }
    
    meta_debug("Refreshing thread list...");
    
    if (account->active && account->active->get_threads) {
        account->active->get_threads(account);
    }
}

static void action_switch_to_messenger(PurpleProtocolAction *action)
{
    PurpleConnection *gc = action->connection;
    MetaAccount *account = META_GC_ACCOUNT(gc);
    
    if (!account) return;
    
    account->mode = META_SERVICE_MESSENGER;
    account->active = account->messenger;
    purple_account_set_int(account->pa, "service_mode", META_SERVICE_MESSENGER);
    
    purple_notify_info(gc, "Meta", "Switched to Messenger",
                      "Active service is now Facebook Messenger.",
                      NULL);
}

static void action_switch_to_instagram(PurpleProtocolAction *action)
{
    PurpleConnection *gc = action->connection;
    MetaAccount *account = META_GC_ACCOUNT(gc);
    
    if (!account) return;
    
    account->mode = META_SERVICE_INSTAGRAM;
    account->active = account->instagram;
    purple_account_set_int(account->pa, "service_mode", META_SERVICE_INSTAGRAM);
    
    purple_notify_info(gc, "Meta", "Switched to Instagram",
                      "Active service is now Instagram DMs.",
                      NULL);
}

static void action_reauthenticate(PurpleProtocolAction *action)
{
    PurpleConnection *gc = action->connection;
    MetaAccount *account = META_GC_ACCOUNT(gc);
    
    if (!account) return;
    
    /* Clear stored tokens */
    g_free(account->access_token);
    g_free(account->session_cookies);
    account->access_token = NULL;
    account->session_cookies = NULL;
    
    purple_account_set_string(account->pa, "access_token", NULL);
    purple_account_set_string(account->pa, "session_cookies", NULL);
    
    purple_notify_info(gc, "Meta", "Credentials cleared",
                      "Please disconnect and reconnect to re-authenticate.",
                      NULL);
}

static GList *meta_protocol_get_actions(PurpleConnection *gc)
{
    GList *actions = NULL;
    PurpleProtocolAction *action;
    
    action = purple_protocol_action_new("Refresh Conversations", 
                                         action_refresh_threads);
    actions = g_list_append(actions, action);
    
    action = purple_protocol_action_new("Switch to Messenger", 
                                         action_switch_to_messenger);
    actions = g_list_append(actions, action);
    
    action = purple_protocol_action_new("Switch to Instagram", 
                                         action_switch_to_instagram);
    actions = g_list_append(actions, action);
    
    action = purple_protocol_action_new("Re-authenticate...", 
                                         action_reauthenticate);
    actions = g_list_append(actions, action);
    
    return actions;
}

/* ============================================================
 * Account Options (Settings UI)
 * ============================================================ */

static GList *meta_protocol_get_account_options(void)
{
    GList *options = NULL;
    PurpleAccountOption *opt;
    
    /* Service mode dropdown */
    GList *mode_list = NULL;
    PurpleKeyValuePair *kvp;
    
    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("Facebook Messenger");
    kvp->value = g_strdup("messenger");
    mode_list = g_list_append(mode_list, kvp);
    
    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("Instagram DMs");
    kvp->value = g_strdup("instagram");
    mode_list = g_list_append(mode_list, kvp);
    
    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("Both (Unified)");
    kvp->value = g_strdup("unified");
    mode_list = g_list_append(mode_list, kvp);
    
    opt = purple_account_option_list_new("Service", "service_mode", mode_list);
    options = g_list_append(options, opt);
    
    /* Show presence toggle */
    opt = purple_account_option_bool_new("Show online status to others",
                                          "show_presence", TRUE);
    options = g_list_append(options, opt);
    
    /* Sync history toggle */
    opt = purple_account_option_bool_new("Sync message history on connect",
                                          "sync_history", TRUE);
    options = g_list_append(options, opt);
    
    /* History limit */
    opt = purple_account_option_int_new("Messages to sync per thread",
                                         "sync_limit", 50);
    options = g_list_append(options, opt);
    
    /* Mark as read automatically */
    opt = purple_account_option_bool_new("Mark messages as read automatically",
                                          "auto_read", TRUE);
    options = g_list_append(options, opt);
    
    /* Debug mode */
    opt = purple_account_option_bool_new("Enable debug logging",
                                          "debug_mode", FALSE);
    options = g_list_append(options, opt);
    
    return options;
}

/* ============================================================
 * Connection Handling
 * ============================================================ */

void meta_login(PurpleAccount *account)
{
    PurpleConnection *gc = purple_account_get_connection(account);
    MetaAccount *ma;
    const char *service_mode_str;
    MetaConfig *config;
    
    meta_debug("Attempting to log in to Meta services...");
    
    /* Get configuration */
    config = meta_config_get();
    
    /* Create account state */
    ma = meta_account_new(account);
    ma->pc = gc;
    ma->state = META_STATE_CONNECTING;
    
    purple_connection_set_protocol_data(gc, ma);
    purple_connection_set_state(gc, PURPLE_CONNECTION_STATE_CONNECTING);
    
    /* Warn user about plaintext storage (once per account) */
    meta_security_warn_plaintext_storage(ma);
    
    /* Determine service mode */
    service_mode_str = purple_account_get_string(account, "service_mode", "messenger");
    if (g_strcmp0(service_mode_str, "instagram") == 0) {
        /* Check if Instagram is enabled in config */
        if (!meta_config_is_instagram_enabled()) {
            purple_connection_error(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
                                    "Instagram is disabled in configuration");
            return;
        }
        ma->mode = META_SERVICE_INSTAGRAM;
        ma->active = ma->instagram;
    } else if (g_strcmp0(service_mode_str, "unified") == 0) {
        ma->mode = META_SERVICE_UNIFIED;
        ma->active = ma->messenger; /* Start with Messenger */
    } else {
        /* Check if Messenger is enabled in config */
        if (!meta_config_is_messenger_enabled()) {
            purple_connection_error(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
                                    "Messenger is disabled in configuration");
            return;
        }
        ma->mode = META_SERVICE_MESSENGER;
        ma->active = ma->messenger;
    }
    
    /* Check for stored access token using secure retrieval */
    ma->access_token = meta_security_retrieve_token(ma, "access_token");
    ma->session_cookies = meta_security_retrieve_token(ma, "session_cookies");
    
    if (ma->access_token && strlen(ma->access_token) > 0) {
        /* Validate token format before using */
        if (!meta_security_validate_token_format(ma->access_token)) {
            meta_warning("Stored access token has invalid format, clearing...");
            meta_security_clear_all_tokens(ma);
            meta_security_free_token(ma->access_token);
            ma->access_token = NULL;
        }
    }
    
    if (ma->access_token && strlen(ma->access_token) > 0) {
        /* We have a token, try to connect directly */
        meta_debug("Found stored access token, attempting direct connection...");
        ma->state = META_STATE_AUTHENTICATING;
        
        /* Validate token and connect */
        if (meta_auth_validate_token(ma)) {
            meta_websocket_connect(ma);
        } else {
            /* Token expired, need to re-authenticate */
            meta_debug("Stored token invalid, initiating OAuth flow...");
            meta_auth_start_oauth(ma);
        }
    } else {
        /* No token, need to authenticate */
        meta_debug("No stored credentials, initiating OAuth flow...");
        meta_auth_start_oauth(ma);
    }
}

void meta_logout(PurpleConnection *gc)
{
    meta_close(gc);
}

void meta_close(PurpleConnection *gc)
{
    MetaAccount *ma = purple_connection_get_protocol_data(gc);
    
    if (!ma) return;
    
    meta_debug("Closing connection...");
    
    /* Disconnect services */
    if (ma->active && ma->active->disconnect) {
        ma->active->disconnect(ma);
    }
    
    /* Close WebSocket */
    meta_websocket_disconnect(ma);
    
    ma->state = META_STATE_DISCONNECTED;
    
    /* Free account data */
    meta_account_free(ma);
    purple_connection_set_protocol_data(gc, NULL);
}

/* ============================================================
 * Messaging
 * ============================================================ */

#if PURPLE_VERSION == 2
int meta_send_im(PurpleConnection *gc, const char *who, const char *message, PurpleMessageFlags flags)
{
    MetaAccount *ma = META_GC_ACCOUNT(gc);
    
    (void)flags; /* unused in our implementation */
#else
int meta_send_im(PurpleConnection *gc, PurpleMessage *msg)
{
    MetaAccount *ma = META_GC_ACCOUNT(gc);
    const char *who = purple_message_get_recipient(msg);
    const char *message = purple_message_get_contents(msg);
#endif
    
    if (!ma || ma->state != META_STATE_CONNECTED) {
        return -1;
    }
    
    if (!ma->active || !ma->active->send_message) {
        meta_error("No active service to send message");
        return -1;
    }
    
    meta_debug("Sending message to %s: %s", who, message);
    
    if (ma->active->send_message(ma, who, message, META_MSG_TEXT)) {
        return 1; /* Success */
    }
    
    return -1; /* Failure */
}

#if PURPLE_VERSION == 2
unsigned int meta_send_typing(PurpleConnection *gc, const char *name,
                               PurpleTypingState state)
{
    MetaAccount *ma = META_GC_ACCOUNT(gc);
    gboolean typing = (state == PURPLE_TYPING);
#else
unsigned int meta_send_typing(PurpleConnection *gc, const char *name,
                               PurpleIMTypingState state)
{
    MetaAccount *ma = META_GC_ACCOUNT(gc);
    gboolean typing = (state == PURPLE_IM_TYPING);
#endif
    
    if (!ma || ma->state != META_STATE_CONNECTED) {
        return 0;
    }
    
    if (ma->active && ma->active->send_typing) {
        ma->active->send_typing(ma, name, typing);
    }
    
    return 0;
}

/* ============================================================
 * Buddy List Operations
 * ============================================================ */

void meta_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
                    PurpleGroup *group, const char *message)
{
    /* Meta doesn't really have a buddy add concept - we sync contacts */
    meta_debug("Add buddy requested for %s (no-op)", 
               purple_buddy_get_name(buddy));
}

void meta_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
                       PurpleGroup *group)
{
    meta_debug("Remove buddy requested for %s (no-op)",
               purple_buddy_get_name(buddy));
}

/* ============================================================
 * Status Handling
 * ============================================================ */

void meta_set_status(PurpleAccount *account, PurpleStatus *status)
{
    MetaAccount *ma = META_ACCOUNT(account);
    PurpleStatusPrimitive prim;
    
    if (!ma || ma->state != META_STATE_CONNECTED) {
        return;
    }
    
    prim = purple_status_type_get_primitive(purple_status_get_status_type(status));
    
    meta_debug("Setting status to %s", 
               purple_primitive_get_name_from_type(prim));
    
    if (ma->active && ma->active->set_presence) {
        ma->active->set_presence(ma, prim);
    }
}

static GList *meta_status_types(PurpleAccount *account)
{
    GList *types = NULL;
    PurpleStatusType *type;
    
    /* Available */
    type = purple_status_type_new_with_attrs(
        PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE, TRUE, FALSE,
        "message", "Message", purple_value_new(G_TYPE_STRING),
        NULL);
    types = g_list_append(types, type);
    
    /* Away */
    type = purple_status_type_new_with_attrs(
        PURPLE_STATUS_AWAY, NULL, NULL, TRUE, TRUE, FALSE,
        "message", "Message", purple_value_new(G_TYPE_STRING),
        NULL);
    types = g_list_append(types, type);
    
    /* Invisible */
    type = purple_status_type_new(
        PURPLE_STATUS_INVISIBLE, NULL, NULL, TRUE);
    types = g_list_append(types, type);
    
    /* Offline */
    type = purple_status_type_new(
        PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE);
    types = g_list_append(types, type);
    
    return types;
}

/* ============================================================
 * Chat (Group) Operations
 * ============================================================ */

GList *meta_chat_info(PurpleConnection *gc)
{
    GList *info = NULL;
    PurpleProtocolChatEntry *pce;
    
    pce = g_new0(PurpleProtocolChatEntry, 1);
    pce->label = "Thread ID";
    pce->identifier = "thread_id";
    pce->required = TRUE;
    info = g_list_append(info, pce);
    
    return info;
}

GHashTable *meta_chat_info_defaults(PurpleConnection *gc, const char *room)
{
    GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                  NULL, g_free);
    
    if (room) {
        g_hash_table_insert(defaults, "thread_id", g_strdup(room));
    }
    
    return defaults;
}

void meta_join_chat(PurpleConnection *gc, GHashTable *components)
{
    MetaAccount *ma = META_GC_ACCOUNT(gc);
    const char *thread_id = g_hash_table_lookup(components, "thread_id");
    
    if (!thread_id) {
        purple_notify_error(gc, "Meta", "Cannot join chat",
                           "No thread ID specified.", NULL);
        return;
    }
    
    meta_debug("Joining chat: %s", thread_id);
    
#if PURPLE_VERSION == 2
    /* Create the chat conversation */
    PurpleConversation *conv = serv_got_joined_chat(gc, 
                                       g_str_hash(thread_id), thread_id);
    
    /* Fetch thread info and participants */
    if (ma->active && ma->active->get_thread) {
        MetaThread *thread = ma->active->get_thread(ma, thread_id);
        if (thread) {
            /* Add participants */
            GList *l;
            for (l = thread->participants; l; l = l->next) {
                MetaUser *user = l->data;
                purple_conv_chat_add_user(PURPLE_CONV_CHAT(conv), user->display_name,
                                          NULL, PURPLE_CBFLAGS_NONE, FALSE);
            }
        }
    }
#else
    /* Create the chat conversation */
    PurpleChatConversation *chat = purple_serv_got_joined_chat(gc, 
                                       g_str_hash(thread_id), thread_id);
    
    /* Fetch thread info and participants */
    if (ma->active && ma->active->get_thread) {
        MetaThread *thread = ma->active->get_thread(ma, thread_id);
        if (thread) {
            /* Add participants */
            GList *l;
            for (l = thread->participants; l; l = l->next) {
                MetaUser *user = l->data;
                purple_chat_conversation_add_user(chat, user->display_name,
                                                   NULL, PURPLE_CHAT_USER_NONE,
                                                   FALSE);
            }
        }
    }
#endif
}

void meta_chat_leave(PurpleConnection *gc, int id)
{
    meta_debug("Leaving chat %d", id);
    /* Nothing special needed for Meta - we just close the window */
}

#if PURPLE_VERSION == 2
int meta_chat_send(PurpleConnection *gc, int id, const char *message, PurpleMessageFlags flags)
{
    MetaAccount *ma = META_GC_ACCOUNT(gc);
    PurpleConversation *conv = purple_find_chat(gc, id);
    const char *thread_id;
    
    (void)flags; /* unused */
    
    if (!conv) {
        return -1;
    }
    
    thread_id = purple_conversation_get_name(conv);
#else
int meta_chat_send(PurpleConnection *gc, int id, PurpleMessage *msg)
{
    MetaAccount *ma = META_GC_ACCOUNT(gc);
    PurpleChatConversation *chat = purple_conversations_find_chat(gc, id);
    const char *thread_id;
    const char *message = purple_message_get_contents(msg);
    
    if (!chat) {
        return -1;
    }
    
    thread_id = purple_conversation_get_name(PURPLE_CONVERSATION(chat));
#endif
    
    if (!ma || ma->state != META_STATE_CONNECTED) {
        return -1;
    }
    
    meta_debug("Sending chat message to %s: %s", thread_id, message);
    
    if (ma->active && ma->active->send_message) {
        if (ma->active->send_message(ma, thread_id, message, META_MSG_TEXT)) {
            return 0; /* Success */
        }
    }
    
    return -1;
}

/* ============================================================
 * Protocol Interface Definition (libpurple 3.0 style)
 * ============================================================ */

static void meta_protocol_init(PurpleProtocol *protocol)
{
    /* Nothing special needed */
}

static void meta_protocol_class_init(PurpleProtocolClass *klass)
{
    klass->login = meta_login;
    klass->close = meta_close;
    klass->status_types = meta_status_types;
}

static void meta_protocol_client_iface_init(PurpleProtocolClientInterface *iface)
{
    iface->get_actions = meta_protocol_get_actions;
    iface->status_text = NULL; /* TODO */
    iface->tooltip_text = NULL; /* TODO */
}

static void meta_protocol_server_iface_init(PurpleProtocolServerInterface *iface)
{
    iface->add_buddy = meta_add_buddy;
    iface->remove_buddy = meta_remove_buddy;
    iface->set_status = meta_set_status;
}

static void meta_protocol_im_iface_init(PurpleProtocolIMInterface *iface)
{
    iface->send = meta_send_im;
    iface->send_typing = meta_send_typing;
}

static void meta_protocol_chat_iface_init(PurpleProtocolChatInterface *iface)
{
    iface->info = meta_chat_info;
    iface->info_defaults = meta_chat_info_defaults;
    iface->join = meta_join_chat;
    iface->leave = meta_chat_leave;
    iface->send = meta_chat_send;
}

/* Define the protocol type */
G_DEFINE_DYNAMIC_TYPE_EXTENDED(
    MetaProtocol, meta_protocol, PURPLE_TYPE_PROTOCOL, 0,
    G_IMPLEMENT_INTERFACE_DYNAMIC(PURPLE_TYPE_PROTOCOL_CLIENT,
                                  meta_protocol_client_iface_init)
    G_IMPLEMENT_INTERFACE_DYNAMIC(PURPLE_TYPE_PROTOCOL_SERVER,
                                  meta_protocol_server_iface_init)
    G_IMPLEMENT_INTERFACE_DYNAMIC(PURPLE_TYPE_PROTOCOL_IM,
                                  meta_protocol_im_iface_init)
    G_IMPLEMENT_INTERFACE_DYNAMIC(PURPLE_TYPE_PROTOCOL_CHAT,
                                  meta_protocol_chat_iface_init)
)

static void meta_protocol_class_finalize(PurpleProtocolClass *klass)
{
    /* Cleanup if needed */
}

/* ============================================================
 * Plugin Loading/Unloading
 * ============================================================ */

static PurpleProtocol *meta_protocol_instance = NULL;

gboolean meta_plugin_load(PurplePlugin *plugin)
{
    MetaConfig *config;
    
    meta_debug("Loading Meta protocol plugin v%s", META_PLUGIN_VERSION);
    
    /* Initialize configuration system */
    config = meta_config_get();
    if (!config) {
        meta_warning("Failed to load configuration, using defaults");
    } else {
        meta_debug("Configuration loaded from: %s", 
                   config->loaded_from ? config->loaded_from : "defaults");
    }
    
    /* Validate configuration */
    gchar *config_error = NULL;
    if (config && !meta_config_validate(config, &config_error)) {
        meta_warning("Configuration validation warning: %s", config_error);
        g_free(config_error);
    }
    
    /* Check if Instagram is enabled in config */
    if (meta_config_is_instagram_enabled()) {
        meta_debug("Instagram service is enabled");
    } else {
        meta_debug("Instagram service is disabled in configuration");
    }
    
    /* Initialize account registry */
    meta_accounts = g_hash_table_new(g_direct_hash, g_direct_equal);
    
    /* Register the protocol type */
    meta_protocol_register_type(G_TYPE_MODULE(plugin));
    
    /* Create and register protocol instance */
    meta_protocol_instance = g_object_new(
        meta_protocol_get_type(),
        "id", META_PLUGIN_ID,
        "name", META_PLUGIN_NAME,
        "options", OPT_PROTO_CHAT_TOPIC | OPT_PROTO_IM_IMAGE,
        NULL
    );
    
    if (!purple_protocols_add(meta_protocol_instance, plugin, NULL)) {
        meta_error("Failed to register protocol");
        g_object_unref(meta_protocol_instance);
        return FALSE;
    }
    
    meta_debug("Meta protocol plugin loaded successfully");
    return TRUE;
}

gboolean meta_plugin_unload(PurplePlugin *plugin)
{
    meta_debug("Unloading Meta protocol plugin");
    
    /* Unregister protocol */
    if (meta_protocol_instance) {
        purple_protocols_remove(meta_protocol_instance, plugin, NULL);
        g_object_unref(meta_protocol_instance);
        meta_protocol_instance = NULL;
    }
    
    /* Cleanup account registry */
    if (meta_accounts) {
        g_hash_table_destroy(meta_accounts);
        meta_accounts = NULL;
    }
    
    /* Free configuration */
    meta_config_free();
    
    return TRUE;
}

/* ============================================================
 * Plugin Information (GPlugin/libpurple 3.0)
 * ============================================================ */

static PurplePluginInfo *plugin_query(GError **error)
{
    GList *account_options = meta_protocol_get_account_options();
    
    return purple_plugin_info_new(
        "id", META_PLUGIN_ID,
        "name", META_PLUGIN_NAME,
        "version", META_PLUGIN_VERSION,
        "category", "Protocol",
        "summary", "Meta protocol plugin for Facebook Messenger and Instagram DMs",
        "description", "Enables Pidgin to connect to Facebook Messenger and "
                       "Instagram Direct Messages using Meta's Graph API and "
                       "WebSocket connections.",
        "authors", (const char *[]) { META_PLUGIN_AUTHOR, NULL },
        "website", META_PLUGIN_WEBSITE,
        "abi-version", PURPLE_ABI_VERSION,
        "flags", PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
        NULL
    );
}

static gboolean plugin_load(PurplePlugin *plugin, GError **error)
{
    return meta_plugin_load(plugin);
}

static gboolean plugin_unload(PurplePlugin *plugin, GError **error)
{
    return meta_plugin_unload(plugin);
}

PURPLE_PLUGIN_INIT(meta, plugin_query, plugin_load, plugin_unload);