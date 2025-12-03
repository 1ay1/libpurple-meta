/**
 * messenger.c
 * 
 * Facebook Messenger service module implementation for libpurple-meta
 * Handles Messenger-specific API calls and message handling
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#include "messenger.h"
#include "../common/meta-auth.h"
#include "../common/meta-websocket.h"
#include <json-glib/json-glib.h>
#include <string.h>
#include <time.h>

/* Rate limiting: max 200 calls per hour */
#define MESSENGER_RATE_LIMIT_CALLS   200
#define MESSENGER_RATE_LIMIT_WINDOW  3600  /* 1 hour in seconds */

/* Presence polling interval */
#define MESSENGER_PRESENCE_POLL_INTERVAL  30  /* seconds */

/* ============================================================
 * Internal Helpers
 * ============================================================ */

static MessengerData *messenger_get_data(MetaAccount *account)
{
    if (!account || !account->messenger) return NULL;
    return (MessengerData *)account->messenger->priv;
}

static gint64 get_timestamp_ms(void)
{
    return g_get_real_time() / 1000;
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

MetaService *messenger_service_new(void)
{
    MetaService *service = g_new0(MetaService, 1);
    MessengerData *data = g_new0(MessengerData, 1);
    
    service->id = "messenger";
    service->display_name = "Facebook Messenger";
    
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
    data->presence_cache = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                  g_free, NULL);
    
    service->priv = data;
    
    return service;
}

void messenger_service_free(MetaService *service)
{
    if (!service) return;
    
    MessengerData *data = (MessengerData *)service->priv;
    if (data) {
        g_free(data->page_access_token);
        g_free(data->page_id);
        g_free(data->user_access_token);
        g_free(data->user_name);
        g_free(data->profile_pic_url);
        g_free(data->thread_sync_cursor);
        
        if (data->presence_cache) {
            g_hash_table_destroy(data->presence_cache);
        }
        
        if (data->presence_poll_handle) {
            g_source_remove(data->presence_poll_handle);
        }
        
        g_free(data);
    }
    
    g_free(service);
}

gboolean messenger_init(MetaAccount *account)
{
    if (!account || !account->messenger) return FALSE;
    
    MessengerData *data = messenger_get_data(account);
    if (!data) return FALSE;
    
    /* Copy access token */
    data->user_access_token = g_strdup(account->access_token);
    
    meta_debug("Messenger service initialized");
    return TRUE;
}

void messenger_cleanup(MetaAccount *account)
{
    if (!account) return;
    
    messenger_stop_presence_polling(account);
    
    meta_debug("Messenger service cleaned up");
}

/* ============================================================
 * Connection
 * ============================================================ */

static gboolean service_connect(MetaAccount *account)
{
    return messenger_connect(account);
}

gboolean messenger_connect(MetaAccount *account)
{
    if (!account) return FALSE;
    
    MessengerData *data = messenger_get_data(account);
    if (!data) {
        messenger_init(account);
        data = messenger_get_data(account);
    }
    
    meta_debug("Connecting to Messenger...");
    
    /* Fetch user profile */
    messenger_fetch_profile_async(account);
    
    /* Start presence polling */
    messenger_start_presence_polling(account);
    
    return TRUE;
}

static void service_disconnect(MetaAccount *account)
{
    messenger_disconnect(account);
}

void messenger_disconnect(MetaAccount *account)
{
    if (!account) return;
    
    meta_debug("Disconnecting from Messenger...");
    
    messenger_stop_presence_polling(account);
    messenger_cleanup(account);
}

static gboolean service_reconnect(MetaAccount *account)
{
    return messenger_reconnect(account);
}

gboolean messenger_reconnect(MetaAccount *account)
{
    messenger_disconnect(account);
    return messenger_connect(account);
}

/* ============================================================
 * Messaging
 * ============================================================ */

static gboolean service_send_message(MetaAccount *account, const char *to,
                                      const char *message, MetaMessageType type)
{
    return messenger_send_message(account, to, message, type);
}

gboolean messenger_send_message(MetaAccount *account, const char *to,
                                 const char *message, MetaMessageType type)
{
    MessengerData *data;
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    gboolean result = FALSE;
    
    if (!account || !to || !message) return FALSE;
    
    data = messenger_get_data(account);
    if (!data) return FALSE;
    
    /* Check rate limiting */
    if (messenger_is_rate_limited(data)) {
        meta_warning("Rate limited, message will be queued");
        /* TODO: Queue message for later */
        return FALSE;
    }
    
    meta_debug("Sending message to %s: %s", to, message);
    
    /* Build message JSON for WebSocket */
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    /* Message metadata */
    json_builder_set_member_name(builder, "type");
    json_builder_add_string_value(builder, "message");
    
    json_builder_set_member_name(builder, "body");
    json_builder_add_string_value(builder, message);
    
    /* Thread key */
    json_builder_set_member_name(builder, "threadKey");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "otherUserFbId");
    json_builder_add_string_value(builder, to);
    json_builder_end_object(builder);
    
    /* Timestamp and ID */
    json_builder_set_member_name(builder, "timestamp");
    json_builder_add_int_value(builder, get_timestamp_ms());
    
    json_builder_set_member_name(builder, "messageId");
    gchar *msg_id = g_uuid_string_random();
    json_builder_add_string_value(builder, msg_id);
    g_free(msg_id);
    
    /* Offline threading ID */
    json_builder_set_member_name(builder, "offlineThreadingId");
    gchar *offline_id = g_strdup_printf("%lld", (long long)get_timestamp_ms());
    json_builder_add_string_value(builder, offline_id);
    g_free(offline_id);
    
    json_builder_end_object(builder);
    
    /* Generate JSON string */
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    /* Send via WebSocket */
    MetaWebSocket *ws = (MetaWebSocket *)account->ws_connection;
    if (ws && meta_websocket_is_ready(ws)) {
        result = meta_websocket_publish_json(ws, META_TOPIC_MESSAGES, json_str);
    } else {
        /* Fallback to HTTP API */
        result = messenger_send_message_http(account, to, message);
    }
    
    /* Record API call for rate limiting */
    messenger_record_api_call(data);
    
    g_free(json_str);
    g_object_unref(gen);
    g_object_unref(builder);
    
    return result;
}

static gboolean messenger_send_message_http(MetaAccount *account, const char *to,
                                             const char *message)
{
    MessengerData *data;
    PurpleHttpRequest *request;
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    gchar *url;
    
    data = messenger_get_data(account);
    if (!data || !data->user_access_token) return FALSE;
    
    /* Build Send API request */
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "recipient");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "id");
    json_builder_add_string_value(builder, to);
    json_builder_end_object(builder);
    
    json_builder_set_member_name(builder, "message");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "text");
    json_builder_add_string_value(builder, message);
    json_builder_end_object(builder);
    
    json_builder_set_member_name(builder, "messaging_type");
    json_builder_add_string_value(builder, "RESPONSE");
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    /* Build URL with access token */
    url = g_strdup_printf("%s?access_token=%s", 
                          MESSENGER_SEND_API, data->user_access_token);
    
    /* Create and send request */
    request = purple_http_request_new(url);
    purple_http_request_set_method(request, "POST");
    purple_http_request_header_set(request, "Content-Type", "application/json");
    purple_http_request_set_contents(request, json_str, strlen(json_str));
    
    purple_http_request(account->pc, request, messenger_send_message_cb, account);
    
    purple_http_request_unref(request);
    g_free(url);
    g_free(json_str);
    g_object_unref(gen);
    g_object_unref(builder);
    
    return TRUE;
}

static void messenger_send_message_cb(PurpleHttpConnection *connection,
                                       PurpleHttpResponse *response,
                                       gpointer user_data)
{
    MetaAccount *account = user_data;
    
    if (!purple_http_response_is_successful(response)) {
        int code = purple_http_response_get_code(response);
        meta_error("Failed to send message via HTTP: %d", code);
        return;
    }
    
    meta_debug("Message sent successfully via HTTP API");
}

static gboolean service_send_typing(MetaAccount *account, const char *to,
                                     gboolean typing)
{
    return messenger_send_typing(account, to, typing);
}

gboolean messenger_send_typing(MetaAccount *account, const char *to,
                                gboolean typing)
{
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    gboolean result = FALSE;
    
    if (!account || !to) return FALSE;
    
    meta_debug("Sending typing indicator to %s: %s", to, typing ? "on" : "off");
    
    /* Build typing indicator JSON */
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "type");
    json_builder_add_string_value(builder, typing ? "typ" : "tyn");
    
    json_builder_set_member_name(builder, "to");
    json_builder_add_string_value(builder, to);
    
    json_builder_set_member_name(builder, "thread");
    json_builder_add_string_value(builder, to);
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    /* Send via WebSocket */
    MetaWebSocket *ws = (MetaWebSocket *)account->ws_connection;
    if (ws && meta_websocket_is_ready(ws)) {
        result = meta_websocket_publish_json(ws, META_TOPIC_TYPING, json_str);
    }
    
    g_free(json_str);
    g_object_unref(gen);
    g_object_unref(builder);
    
    return result;
}

static gboolean service_mark_read(MetaAccount *account, const char *thread_id,
                                   const char *message_id)
{
    return messenger_mark_read(account, thread_id, message_id);
}

gboolean messenger_mark_read(MetaAccount *account, const char *thread_id,
                              const char *message_id)
{
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    gboolean result = FALSE;
    
    if (!account || !thread_id) return FALSE;
    
    meta_debug("Marking as read: thread=%s, message=%s", 
               thread_id, message_id ? message_id : "(latest)");
    
    /* Build mark read JSON */
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "type");
    json_builder_add_string_value(builder, "mark_read");
    
    json_builder_set_member_name(builder, "threadKey");
    json_builder_add_string_value(builder, thread_id);
    
    if (message_id) {
        json_builder_set_member_name(builder, "watermarkTimestamp");
        json_builder_add_string_value(builder, message_id);
    }
    
    json_builder_set_member_name(builder, "timestamp");
    json_builder_add_int_value(builder, get_timestamp_ms());
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    /* Send via WebSocket */
    MetaWebSocket *ws = (MetaWebSocket *)account->ws_connection;
    if (ws && meta_websocket_is_ready(ws)) {
        result = meta_websocket_publish_json(ws, META_TOPIC_READ_RECEIPTS, json_str);
    }
    
    g_free(json_str);
    g_object_unref(gen);
    g_object_unref(builder);
    
    return result;
}

gboolean messenger_send_reaction(MetaAccount *account, const char *message_id,
                                  const char *emoji)
{
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    gboolean result = FALSE;
    
    if (!account || !message_id) return FALSE;
    
    meta_debug("Sending reaction to message %s: %s", 
               message_id, emoji ? emoji : "(remove)");
    
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "type");
    json_builder_add_string_value(builder, "reaction");
    
    json_builder_set_member_name(builder, "messageId");
    json_builder_add_string_value(builder, message_id);
    
    if (emoji) {
        json_builder_set_member_name(builder, "reaction");
        json_builder_add_string_value(builder, emoji);
    } else {
        json_builder_set_member_name(builder, "action");
        json_builder_add_string_value(builder, "remove");
    }
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    MetaWebSocket *ws = (MetaWebSocket *)account->ws_connection;
    if (ws && meta_websocket_is_ready(ws)) {
        result = meta_websocket_publish_json(ws, META_TOPIC_MESSAGES, json_str);
    }
    
    g_free(json_str);
    g_object_unref(gen);
    g_object_unref(builder);
    
    return result;
}

/* ============================================================
 * Attachments
 * ============================================================ */

static gboolean service_upload_media(MetaAccount *account, const char *thread_id,
                                      const char *filepath, MetaMessageType type)
{
    MessengerAttachmentType attach_type;
    
    switch (type) {
        case META_MSG_IMAGE:
            attach_type = MESSENGER_ATTACH_IMAGE;
            break;
        case META_MSG_VIDEO:
            attach_type = MESSENGER_ATTACH_VIDEO;
            break;
        case META_MSG_AUDIO:
            attach_type = MESSENGER_ATTACH_AUDIO;
            break;
        default:
            attach_type = MESSENGER_ATTACH_FILE;
            break;
    }
    
    return messenger_send_attachment(account, thread_id, filepath, attach_type);
}

gboolean messenger_send_attachment(MetaAccount *account, const char *to,
                                    const char *filepath,
                                    MessengerAttachmentType type)
{
    MessengerData *data;
    PurpleHttpRequest *request;
    gchar *url;
    gchar *file_contents;
    gsize file_size;
    GError *error = NULL;
    const char *attach_type_str;
    
    if (!account || !to || !filepath) return FALSE;
    
    data = messenger_get_data(account);
    if (!data || !data->user_access_token) return FALSE;
    
    /* Read file */
    if (!g_file_get_contents(filepath, &file_contents, &file_size, &error)) {
        meta_error("Failed to read file %s: %s", filepath, error->message);
        g_error_free(error);
        return FALSE;
    }
    
    /* Determine attachment type string */
    switch (type) {
        case MESSENGER_ATTACH_IMAGE:
            attach_type_str = "image";
            break;
        case MESSENGER_ATTACH_VIDEO:
            attach_type_str = "video";
            break;
        case MESSENGER_ATTACH_AUDIO:
            attach_type_str = "audio";
            break;
        case MESSENGER_ATTACH_FILE:
        default:
            attach_type_str = "file";
            break;
    }
    
    meta_debug("Uploading %s attachment to %s", attach_type_str, to);
    
    /* Build multipart form request */
    url = g_strdup_printf("%s?access_token=%s",
                          MESSENGER_SEND_API, data->user_access_token);
    
    /* Build JSON part for recipient and attachment type */
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "recipient");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "id");
    json_builder_add_string_value(builder, to);
    json_builder_end_object(builder);
    
    json_builder_set_member_name(builder, "message");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "attachment");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "type");
    json_builder_add_string_value(builder, attach_type_str);
    json_builder_set_member_name(builder, "payload");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "is_reusable");
    json_builder_add_boolean_value(builder, TRUE);
    json_builder_end_object(builder);
    json_builder_end_object(builder);
    json_builder_end_object(builder);
    
    json_builder_end_object(builder);
    
    JsonGenerator *gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    gchar *json_str = json_generator_to_data(gen, NULL);
    
    /* Create request - in practice would need proper multipart encoding */
    request = purple_http_request_new(url);
    purple_http_request_set_method(request, "POST");
    purple_http_request_header_set(request, "Content-Type", "application/json");
    purple_http_request_set_contents(request, json_str, strlen(json_str));
    
    purple_http_request(account->pc, request, messenger_attachment_cb, account);
    
    purple_http_request_unref(request);
    g_free(url);
    g_free(json_str);
    g_free(file_contents);
    g_object_unref(gen);
    g_object_unref(builder);
    
    return TRUE;
}

static void messenger_attachment_cb(PurpleHttpConnection *connection,
                                     PurpleHttpResponse *response,
                                     gpointer user_data)
{
    if (!purple_http_response_is_successful(response)) {
        int code = purple_http_response_get_code(response);
        meta_error("Failed to upload attachment: %d", code);
        return;
    }
    
    meta_debug("Attachment uploaded successfully");
}

static gchar *service_download_media(MetaAccount *account, const char *media_url)
{
    return messenger_download_attachment(account, media_url);
}

gchar *messenger_download_attachment(MetaAccount *account,
                                      const char *attachment_url)
{
    /* For now, just return the URL - actual download would be async */
    meta_debug("Download requested for: %s", attachment_url);
    return g_strdup(attachment_url);
}

/* ============================================================
 * Thread Management
 * ============================================================ */

static GList *service_get_threads(MetaAccount *account)
{
    return messenger_get_threads(account);
}

GList *messenger_get_threads(MetaAccount *account)
{
    MessengerData *data;
    PurpleHttpRequest *request;
    gchar *url;
    GList *threads = NULL;
    
    if (!account) return NULL;
    
    data = messenger_get_data(account);
    if (!data || !data->user_access_token) return NULL;
    
    meta_debug("Fetching conversation threads...");
    
    /* Build Graph API request */
    url = messenger_build_api_url(MESSENGER_CONVERSATIONS_API,
                                   data->user_access_token,
                                   "fields", "participants,updated_time,unread_count",
                                   "limit", "50",
                                   NULL);
    
    request = purple_http_request_new(url);
    purple_http_request_set_method(request, "GET");
    
    purple_http_request(account->pc, request, messenger_threads_cb, account);
    
    purple_http_request_unref(request);
    g_free(url);
    
    messenger_record_api_call(data);
    
    return threads;  /* Will be populated async */
}

static void messenger_threads_cb(PurpleHttpConnection *connection,
                                  PurpleHttpResponse *response,
                                  gpointer user_data)
{
    MetaAccount *account = user_data;
    const gchar *response_data;
    gsize response_len;
    GList *threads;
    
    if (!purple_http_response_is_successful(response)) {
        meta_error("Failed to fetch threads");
        return;
    }
    
    response_data = purple_http_response_get_data(response, &response_len);
    
    threads = messenger_parse_threads(response_data);
    
    /* Store threads in account cache */
    for (GList *l = threads; l; l = l->next) {
        MetaThread *thread = l->data;
        g_hash_table_insert(account->threads, g_strdup(thread->id), thread);
        
        /* Create buddy list entries for 1:1 threads */
        if (!thread->is_group && thread->participants) {
            MetaUser *user = thread->participants->data;
            PurpleBuddy *buddy = purple_blist_find_buddy(account->pa, user->id);
            if (!buddy) {
                buddy = purple_buddy_new(account->pa, user->id, user->display_name);
                purple_blist_add_buddy(buddy, NULL, NULL, NULL);
            }
        }
    }
    
    g_list_free(threads);
    
    meta_debug("Thread sync complete");
}

static MetaThread *service_get_thread(MetaAccount *account, const char *thread_id)
{
    return messenger_get_thread(account, thread_id);
}

MetaThread *messenger_get_thread(MetaAccount *account, const char *thread_id)
{
    if (!account || !thread_id) return NULL;
    
    return g_hash_table_lookup(account->threads, thread_id);
}

static GList *service_get_thread_messages(MetaAccount *account,
                                           const char *thread_id,
                                           int limit, const char *before_cursor)
{
    return messenger_get_thread_messages(account, thread_id, limit, before_cursor);
}

GList *messenger_get_thread_messages(MetaAccount *account,
                                      const char *thread_id,
                                      int limit,
                                      const char *before_cursor)
{
    MessengerData *data;
    PurpleHttpRequest *request;
    gchar *url;
    gchar *limit_str;
    
    if (!account || !thread_id) return NULL;
    
    data = messenger_get_data(account);
    if (!data || !data->user_access_token) return NULL;
    
    meta_debug("Fetching messages for thread %s", thread_id);
    
    limit_str = g_strdup_printf("%d", limit > 0 ? limit : 50);
    
    gchar *endpoint = g_strdup_printf("%s/%s/messages", 
                                       MESSENGER_GRAPH_API, thread_id);
    
    if (before_cursor) {
        url = messenger_build_api_url(endpoint, data->user_access_token,
                                       "fields", "message,created_time,from",
                                       "limit", limit_str,
                                       "before", before_cursor,
                                       NULL);
    } else {
        url = messenger_build_api_url(endpoint, data->user_access_token,
                                       "fields", "message,created_time,from",
                                       "limit", limit_str,
                                       NULL);
    }
    
    request = purple_http_request_new(url);
    purple_http_request_set_method(request, "GET");
    
    purple_http_request(account->pc, request, messenger_messages_cb, account);
    
    purple_http_request_unref(request);
    g_free(url);
    g_free(endpoint);
    g_free(limit_str);
    
    messenger_record_api_call(data);
    
    return NULL;  /* Async */
}

static void messenger_messages_cb(PurpleHttpConnection *connection,
                                   PurpleHttpResponse *response,
                                   gpointer user_data)
{
    const gchar *response_data;
    gsize response_len;
    GList *messages;
    
    if (!purple_http_response_is_successful(response)) {
        meta_error("Failed to fetch messages");
        return;
    }
    
    response_data = purple_http_response_get_data(response, &response_len);
    messages = messenger_parse_messages(response_data);
    
    /* Messages are delivered to libpurple via conversation */
    /* For history sync, we'd add them to the conversation log */
    
    g_list_free_full(messages, (GDestroyNotify)g_free);  /* TODO: proper free */
}

gchar *messenger_create_group(MetaAccount *account, const char *name,
                               GList *participants)
{
    meta_debug("Creating group chat: %s", name);
    /* Group creation would go through a different API endpoint */
    return NULL;  /* TODO */
}

gboolean messenger_add_participant(MetaAccount *account, const char *thread_id,
                                    const char *user_id)
{
    meta_debug("Adding %s to thread %s", user_id, thread_id);
    return FALSE;  /* TODO */
}

gboolean messenger_remove_participant(MetaAccount *account,
                                       const char *thread_id,
                                       const char *user_id)
{
    meta_debug("Removing %s from thread %s", user_id, thread_id);
    return FALSE;  /* TODO */
}

/* ============================================================
 * Presence
 * ============================================================ */

static void service_set_presence(MetaAccount *account, PurpleStatusPrimitive status)
{
    messenger_set_presence(account, status);
}

void messenger_set_presence(MetaAccount *account, PurpleStatusPrimitive status)
{
    JsonBuilder *builder;
    JsonGenerator *gen;
    gchar *json_str;
    const char *presence_str;
    
    if (!account) return;
    
    switch (status) {
        case PURPLE_STATUS_AVAILABLE:
            presence_str = "active";
            break;
        case PURPLE_STATUS_AWAY:
            presence_str = "idle";
            break;
        case PURPLE_STATUS_INVISIBLE:
        case PURPLE_STATUS_OFFLINE:
            presence_str = "offline";
            break;
        default:
            presence_str = "active";
    }
    
    meta_debug("Setting presence to: %s", presence_str);
    
    builder = json_builder_new();
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "type");
    json_builder_add_string_value(builder, "presence");
    
    json_builder_set_member_name(builder, "status");
    json_builder_add_string_value(builder, presence_str);
    
    json_builder_end_object(builder);
    
    gen = json_generator_new();
    json_generator_set_root(gen, json_builder_get_root(builder));
    json_str = json_generator_to_data(gen, NULL);
    
    MetaWebSocket *ws = (MetaWebSocket *)account->ws_connection;
    if (ws && meta_websocket_is_ready(ws)) {
        meta_websocket_publish_json(ws, META_TOPIC_PRESENCE, json_str);
    }
    
    g_free(json_str);
    g_object_unref(gen);
    g_object_unref(builder);
}

PurpleStatusPrimitive messenger_get_presence(MetaAccount *account,
                                              const char *user_id)
{
    MessengerData *data;
    gpointer value;
    
    if (!account || !user_id) return PURPLE_STATUS_OFFLINE;
    
    data = messenger_get_data(account);
    if (!data) return PURPLE_STATUS_OFFLINE;
    
    value = g_hash_table_lookup(data->presence_cache, user_id);
    if (!value) return PURPLE_STATUS_OFFLINE;
    
    gint64 last_active = GPOINTER_TO_SIZE(value);
    gint64 now = time(NULL);
    
    /* Consider active if seen in last 5 minutes */
    if (now - last_active < 300) {
        return PURPLE_STATUS_AVAILABLE;
    } else if (now - last_active < 3600) {
        return PURPLE_STATUS_AWAY;
    }
    
    return PURPLE_STATUS_OFFLINE;
}

static gboolean messenger_presence_poll_cb(gpointer user_data)
{
    MetaAccount *account = user_data;
    
    /* Presence is typically received via WebSocket, but we can poll as fallback */
    meta_debug("Presence poll tick");
    
    return G_SOURCE_CONTINUE;
}

void messenger_start_presence_polling(MetaAccount *account)
{
    MessengerData *data;
    
    if (!account) return;
    
    data = messenger_get_data(account);
    if (!data) return;
    
    if (data->presence_poll_handle) {
        return;  /* Already polling */
    }
    
    data->presence_poll_handle = g_timeout_add_seconds(
        MESSENGER_PRESENCE_POLL_INTERVAL,
        messenger_presence_poll_cb,
        account);
    
    meta_debug("Presence polling started");
}

void messenger_stop_presence_polling(MetaAccount *account)
{
    MessengerData *data;
    
    if (!account) return;
    
    data = messenger_get_data(account);
    if (!data) return;
    
    if (data->presence_poll_handle) {
        g_source_remove(data->presence_poll_handle);
        data->presence_poll_handle = 0;
    }
    
    meta_debug("Presence polling stopped");
}

/* ============================================================
 * User Profiles
 * ============================================================ */

static void messenger_fetch_profile_async(MetaAccount *account)
{
    MessengerData *data;
    PurpleHttpRequest *request;
    gchar *url;
    
    if (!account) return;
    
    data = messenger_get_data(account);
    if (!data || !data->user_access_token) return;
    
    url = messenger_build_api_url(MESSENGER_PROFILE_API,
                                   data->user_access_token,
                                   "fields", "id,name,picture",
                                   NULL);
    
    request = purple_http_request_new(url);
    purple_http_request_set_method(request, "GET");
    
    purple_http_request(account->pc, request, messenger_profile_cb, account);
    
    purple_http_request_unref(request);
    g_free(url);
}

static void messenger_profile_cb(PurpleHttpConnection *connection,
                                  PurpleHttpResponse *response,
                                  gpointer user_data)
{
    MetaAccount *account = user_data;
    MessengerData *data;
    const gchar *response_data;
    gsize response_len;
    JsonParser *parser;
    JsonObject *root;
    
    if (!purple_http_response_is_successful(response)) {
        meta_warning("Failed to fetch user profile");
        return;
    }
    
    data = messenger_get_data(account);
    if (!data) return;
    
    response_data = purple_http_response_get_data(response, &response_len);
    
    parser = json_parser_new();
    if (json_parser_load_from_data(parser, response_data, response_len, NULL)) {
        root = json_node_get_object(json_parser_get_root(parser));
        
        g_free(account->user_id);
        account->user_id = g_strdup(json_object_get_string_member(root, "id"));
        
        g_free(data->user_name);
        data->user_name = g_strdup(json_object_get_string_member(root, "name"));
        
        if (json_object_has_member(root, "picture")) {
            JsonObject *picture = json_object_get_object_member(root, "picture");
            if (json_object_has_member(picture, "data")) {
                JsonObject *pic_data = json_object_get_object_member(picture, "data");
                g_free(data->profile_pic_url);
                data->profile_pic_url = g_strdup(
                    json_object_get_string_member(pic_data, "url"));
            }
        }
        
        meta_debug("Profile fetched: %s (%s)", data->user_name, account->user_id);
    }
    
    g_object_unref(parser);
}

MetaUser *messenger_get_user_profile(MetaAccount *account, const char *user_id)
{
    if (!account || !user_id) return NULL;
    
    return g_hash_table_lookup(account->users, user_id);
}

GList *messenger_search_users(MetaAccount *account, const char *query)
{
    meta_debug("Searching users: %s", query);
    /* User search would use Graph API search endpoint */
    return NULL;  /* TODO */
}

/* ============================================================
 * Utility Functions
 * ============================================================ */

GList *messenger_parse_messages(const char *json_str)
{
    GList *messages = NULL;
    JsonParser *parser;
    JsonObject *root;
    JsonArray *data_array;
    
    if (!json_str) return NULL;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, json_str, -1, NULL)) {
        g_object_unref(parser);
        return NULL;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    if (!json_object_has_member(root, "data")) {
        g_object_unref(parser);
        return NULL;
    }
    
    data_array = json_object_get_array_member(root, "data");
    guint count = json_array_get_length(data_array);
    
    for (guint i = 0; i < count; i++) {
        JsonObject *msg_obj = json_array_get_object_element(data_array, i);
        MetaMessage *msg = g_new0(MetaMessage, 1);
        
        msg->id = g_strdup(json_object_get_string_member(msg_obj, "id"));
        msg->text = g_strdup(json_object_get_string_member_with_default(
                                msg_obj, "message", ""));
        
        if (json_object_has_member(msg_obj, "from")) {
            JsonObject *from = json_object_get_object_member(msg_obj, "from");
            msg->sender_id = g_strdup(json_object_get_string_member(from, "id"));
        }
        
        /* Parse timestamp (ISO 8601) */
        const char *created = json_object_get_string_member_with_default(
                                  msg_obj, "created_time", NULL);
        if (created) {
            GDateTime *dt = g_date_time_new_from_iso8601(created, NULL);
            if (dt) {
                msg->timestamp = g_date_time_to_unix(dt) * 1000;
                g_date_time_unref(dt);
            }
        }
        
        msg->type = META_MSG_TEXT;
        
        messages = g_list_append(messages, msg);
    }
    
    g_object_unref(parser);
    return messages;
}

GList *messenger_parse_threads(const char *json_str)
{
    GList *threads = NULL;
    JsonParser *parser;
    JsonObject *root;
    JsonArray *data_array;
    
    if (!json_str) return NULL;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, json_str, -1, NULL)) {
        g_object_unref(parser);
        return NULL;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    if (!json_object_has_member(root, "data")) {
        g_object_unref(parser);
        return NULL;
    }
    
    data_array = json_object_get_array_member(root, "data");
    guint count = json_array_get_length(data_array);
    
    for (guint i = 0; i < count; i++) {
        JsonObject *thread_obj = json_array_get_object_element(data_array, i);
        MetaThread *thread = g_new0(MetaThread, 1);
        
        thread->id = g_strdup(json_object_get_string_member(thread_obj, "id"));
        
        if (json_object_has_member(thread_obj, "participants")) {
            JsonObject *participants = json_object_get_object_member(
                                          thread_obj, "participants");
            JsonArray *part_data = json_object_get_array_member(participants, "data");
            guint part_count = json_array_get_length(part_data);
            
            thread->is_group = (part_count > 2);
            
            for (guint j = 0; j < part_count; j++) {
                JsonObject *part = json_array_get_object_element(part_data, j);
                MetaUser *user = g_new0(MetaUser, 1);
                
                user->id = g_strdup(json_object_get_string_member(part, "id"));
                user->display_name = g_strdup(
                    json_object_get_string_member_with_default(part, "name", user->id));
                
                thread->participants = g_list_append(thread->participants, user);
            }
        }
        
        thread->unread_count = json_object_get_int_member_with_default(
                                  thread_obj, "unread_count", 0);
        
        /* Parse updated_time */
        const char *updated = json_object_get_string_member_with_default(
                                 thread_obj, "updated_time", NULL);
        if (updated) {
            GDateTime *dt = g_date_time_new_from_iso8601(updated, NULL);
            if (dt) {
                thread->last_activity = g_date_time_to_unix(dt) * 1000;
                g_date_time_unref(dt);
            }
        }
        
        threads = g_list_append(threads, thread);
    }
    
    g_object_unref(parser);
    return threads;
}

gchar *messenger_build_api_url(const char *endpoint, const char *access_token, ...)
{
    GString *url;
    va_list args;
    const char *key, *value;
    gboolean first_param;
    
    url = g_string_new(endpoint);
    g_string_append_printf(url, "?access_token=%s", access_token);
    first_param = FALSE;
    
    va_start(args, access_token);
    while ((key = va_arg(args, const char *)) != NULL) {
        value = va_arg(args, const char *);
        if (value) {
            gchar *encoded_value = g_uri_escape_string(value, NULL, TRUE);
            g_string_append_printf(url, "&%s=%s", key, encoded_value);
            g_free(encoded_value);
        }
    }
    va_end(args);
    
    return g_string_free(url, FALSE);
}

gboolean messenger_is_rate_limited(MessengerData *data)
{
    gint64 now = time(NULL);
    
    if (!data) return FALSE;
    
    /* Reset counter if window has passed */
    if (now - data->last_api_call > MESSENGER_RATE_LIMIT_WINDOW) {
        data->api_call_count = 0;
        data->last_api_call = now;
    }
    
    return data->api_call_count >= MESSENGER_RATE_LIMIT_CALLS;
}

void messenger_record_api_call(MessengerData *data)
{
    if (!data) return;
    
    data->api_call_count++;
    data->last_api_call = time(NULL);
}