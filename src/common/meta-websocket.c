/**
 * meta-websocket.c
 * 
 * WebSocket connection handler implementation for libpurple-meta
 * Manages persistent connections to Meta's messaging endpoints
 * 
 * Meta uses a weird MQTT-over-WebSocket thing that's not quite standard MQTT.
 * Some of the packet formats are close but not identical. Had to reverse
 * engineer a bunch of this from browser network traces.
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#include "meta-websocket.h"
#include "meta-auth.h"
#include "meta-config.h"
#include "meta-security.h"
#include <json-glib/json-glib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

/* ============================================================
 * Internal Helpers
 * ============================================================ */

/* Packet IDs wrap around at 65535 - zero is reserved/invalid */

static guint16 meta_ws_next_packet_id(MetaWebSocket *ws)
{
    if (ws->next_packet_id == 0) {
        ws->next_packet_id = 1;
    }
    return ws->next_packet_id++;
}

static gint64 meta_get_timestamp_ms(void)
{
    return g_get_real_time() / 1000;
}

/* ============================================================
 * WebSocket Creation/Destruction
 * ============================================================ */

MetaWebSocket *meta_websocket_new(MetaAccount *account)
{
    MetaWebSocket *ws = g_new0(MetaWebSocket, 1);
    guint reconnect_delay;
    
    ws->account = account;
    ws->state = META_WS_STATE_DISCONNECTED;
    ws->next_packet_id = 1;
    
    /* Get reconnect delay from config or use default */
    reconnect_delay = meta_config_get_ws_reconnect_delay();
    ws->reconnect_delay = (reconnect_delay > 0) ? reconnect_delay : META_WS_RECONNECT_DELAY;
    
    /* Initialize buffers */
    ws->read_buffer = g_byte_array_new();
    ws->write_queue = g_queue_new();
    
    /* Initialize pending ACKs table */
    ws->pending_acks = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                              NULL, (GDestroyNotify)meta_mqtt_packet_free);
    
    return ws;
}

void meta_websocket_free(MetaWebSocket *ws)
{
    if (!ws) return;
    
    /* Stop timers */
    meta_websocket_stop_keepalive(ws);
    meta_websocket_cancel_reconnect(ws);
    
    /* Close connection */
    if (ws->ssl_conn) {
        purple_ssl_close(ws->ssl_conn);
        ws->ssl_conn = NULL;
    }
    
    if (ws->channel) {
        g_io_channel_unref(ws->channel);
        ws->channel = NULL;
    }
    
    if (ws->read_handle) {
        g_source_remove(ws->read_handle);
    }
    if (ws->write_handle) {
        g_source_remove(ws->write_handle);
    }
    
    /* Free soup resources if used */
    if (ws->soup_websocket) {
        g_object_unref(ws->soup_websocket);
    }
    if (ws->soup_session) {
        g_object_unref(ws->soup_session);
    }
    
    /* Free buffers */
    g_byte_array_free(ws->read_buffer, TRUE);
    
    /* Free write queue */
    while (!g_queue_is_empty(ws->write_queue)) {
        GByteArray *data = g_queue_pop_head(ws->write_queue);
        g_byte_array_free(data, TRUE);
    }
    g_queue_free(ws->write_queue);
    
    /* Free pending ACKs */
    g_hash_table_destroy(ws->pending_acks);
    
    /* Free subscriptions */
    g_list_free_full(ws->subscriptions, g_free);
    
    /* Free sync token */
    g_free(ws->sync_token);
    
    g_free(ws);
}

/* ============================================================
 * Connection Management
 * ============================================================ */

const char *meta_websocket_get_endpoint(MetaServiceMode mode)
{
    const gchar *endpoint;
    
    switch (mode) {
        case META_SERVICE_INSTAGRAM:
            endpoint = meta_config_get_ig_realtime_url();
            if (endpoint && endpoint[0] != '\0') {
                return endpoint;
            }
            return INSTAGRAM_REALTIME_URL;
        case META_SERVICE_MESSENGER:
        case META_SERVICE_UNIFIED:
        default:
            endpoint = meta_config_get_mqtt_endpoint();
            if (endpoint && endpoint[0] != '\0') {
                return endpoint;
            }
            return META_MQTT_ENDPOINT;
    }
}

gchar *meta_websocket_generate_session_id(void)
{
    guint8 random_bytes[16];
    GString *session_id = g_string_new(NULL);
    
    for (int i = 0; i < 16; i++) {
        random_bytes[i] = g_random_int_range(0, 256);
    }
    
    for (int i = 0; i < 16; i++) {
        g_string_append_printf(session_id, "%02x", random_bytes[i]);
    }
    
    return g_string_free(session_id, FALSE);
}

static void meta_websocket_ssl_connected(gpointer data, PurpleSslConnection *ssl,
                                          PurpleInputCondition cond);
static void meta_websocket_ssl_error(PurpleSslConnection *ssl,
                                      PurpleSslErrorType error, gpointer data);
static void meta_websocket_ssl_input(gpointer data, PurpleSslConnection *ssl,
                                      PurpleInputCondition cond);

gboolean meta_websocket_connect(MetaAccount *account)
{
    return meta_websocket_connect_full(account, NULL, NULL, NULL, NULL);
}

gboolean meta_websocket_connect_full(MetaAccount *account,
                                      MetaWsConnectedCallback on_connected,
                                      MetaWsMessageCallback on_message,
                                      MetaWsDisconnectedCallback on_disconnected,
                                      gpointer user_data)
{
    MetaWebSocket *ws;
    const char *endpoint;
    gchar *host = NULL;
    gint port = 443;
    
    if (!account || !account->access_token) {
        meta_error("Cannot connect: no account or access token");
        return FALSE;
    }
    
    /* Create or reuse WebSocket */
    if (account->ws_connection) {
        ws = (MetaWebSocket *)account->ws_connection;
        if (ws->state == META_WS_STATE_CONNECTED || 
            ws->state == META_WS_STATE_READY) {
            meta_debug("Already connected");
            return TRUE;
        }
    } else {
        ws = meta_websocket_new(account);
        account->ws_connection = ws;
    }
    
    /* Set callbacks */
    ws->on_connected = on_connected;
    ws->on_message = on_message;
    ws->on_disconnected = on_disconnected;
    ws->callback_data = user_data;
    
    /* Get endpoint */
    endpoint = meta_websocket_get_endpoint(account->mode);
    meta_debug("Connecting to %s", endpoint);
    
    /* Parse URL to get host */
    if (g_str_has_prefix(endpoint, "wss://")) {
        const char *path_start;
        host = g_strdup(endpoint + 6);
        path_start = strchr(host, '/');
        if (path_start) {
            host[path_start - host] = '\0';
        }
    } else {
        meta_error("Invalid WebSocket URL: %s", endpoint);
        return FALSE;
    }
    
    ws->state = META_WS_STATE_CONNECTING;
    
    purple_connection_update_progress(account->pc, "Connecting to Meta...", 1, 4);
    
    /* Start SSL connection */
    ws->ssl_conn = purple_ssl_connect(account->pa, host, port,
                                       meta_websocket_ssl_connected,
                                       meta_websocket_ssl_error,
                                       ws);
    
    g_free(host);
    
    if (!ws->ssl_conn) {
        meta_error("Failed to initiate SSL connection");
        ws->state = META_WS_STATE_ERROR;
        return FALSE;
    }
    
    return TRUE;
}

static void meta_websocket_ssl_connected(gpointer data, PurpleSslConnection *ssl,
                                          PurpleInputCondition cond)
{
    MetaWebSocket *ws = data;
    MetaAccount *account = ws->account;
    const char *endpoint = meta_websocket_get_endpoint(account->mode);
    gchar *host = NULL;
    gchar *path = "/chat";
    GString *request;
    gchar *session_id;
    
    meta_debug("SSL connected, sending WebSocket upgrade request");
    
    /* Parse host and path from endpoint */
    if (g_str_has_prefix(endpoint, "wss://")) {
        const char *path_start;
        host = g_strdup(endpoint + 6);
        path_start = strchr(host, '/');
        if (path_start) {
            path = g_strdup(path_start);
            host[path_start - host] = '\0';
        }
    }
    
    /* Generate WebSocket key */
    guint8 key_bytes[16];
    for (int i = 0; i < 16; i++) {
        key_bytes[i] = g_random_int_range(0, 256);
    }
    gchar *ws_key = g_base64_encode(key_bytes, 16);
    
    session_id = meta_websocket_generate_session_id();
    
    /* Build WebSocket upgrade request */
    request = g_string_new(NULL);
    g_string_append_printf(request, "GET %s HTTP/1.1\r\n", path);
    g_string_append_printf(request, "Host: %s\r\n", host);
    g_string_append(request, "Upgrade: websocket\r\n");
    g_string_append(request, "Connection: Upgrade\r\n");
    g_string_append_printf(request, "Sec-WebSocket-Key: %s\r\n", ws_key);
    g_string_append(request, "Sec-WebSocket-Version: 13\r\n");
    g_string_append_printf(request, "Origin: %s\r\n", META_MQTT_ORIGIN);
    g_string_append(request, "Sec-WebSocket-Protocol: mqtt\r\n");
    
    /* Add cookies if available */
    if (account->session_cookies) {
        MetaSessionCookies *cookies = meta_auth_load_cookies(account);
        if (cookies) {
            gchar *cookie_header = meta_auth_cookies_to_header(cookies);
            if (cookie_header) {
                g_string_append_printf(request, "Cookie: %s\r\n", cookie_header);
                g_free(cookie_header);
            }
            meta_session_cookies_free(cookies);
        }
    }
    
    g_string_append(request, "\r\n");
    
    /* Send the request */
    purple_ssl_write(ssl, request->str, request->len);
    
    g_string_free(request, TRUE);
    g_free(ws_key);
    g_free(session_id);
    g_free(host);
    
    /* Set up input handler to receive response */
    purple_ssl_input_add(ssl, meta_websocket_ssl_input, ws);
    
    purple_connection_update_progress(account->pc, "Upgrading to WebSocket...", 2, 4);
}

static void meta_websocket_ssl_error(PurpleSslConnection *ssl,
                                      PurpleSslErrorType error, gpointer data)
{
    MetaWebSocket *ws = data;
    const char *error_msg;
    
    switch (error) {
        case PURPLE_SSL_CONNECT_FAILED:
            error_msg = "SSL connection failed";
            break;
        case PURPLE_SSL_HANDSHAKE_FAILED:
            error_msg = "SSL handshake failed";
            break;
        case PURPLE_SSL_CERTIFICATE_INVALID:
            error_msg = "Invalid SSL certificate";
            break;
        default:
            error_msg = "Unknown SSL error";
    }
    
    meta_error("SSL error: %s", error_msg);
    
    ws->ssl_conn = NULL;
    ws->state = META_WS_STATE_ERROR;
    
    meta_websocket_on_error(ws, error_msg);
}

static void meta_websocket_ssl_input(gpointer data, PurpleSslConnection *ssl,
                                      PurpleInputCondition cond)
{
    MetaWebSocket *ws = data;
    guint8 buffer[4096];
    gssize len;
    
    len = purple_ssl_read(ssl, buffer, sizeof(buffer));
    
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;  /* No data available yet */
        }
        meta_error("SSL read error: %s", g_strerror(errno));
        meta_websocket_on_error(ws, "Read error");
        return;
    }
    
    if (len == 0) {
        meta_debug("Connection closed by server");
        meta_websocket_on_disconnected(ws, "Connection closed");
        return;
    }
    
    /* Append to read buffer */
    g_byte_array_append(ws->read_buffer, buffer, len);
    
    /* Process the data */
    meta_websocket_on_data(ws, ws->read_buffer->data, ws->read_buffer->len);
}

void meta_websocket_disconnect(MetaAccount *account)
{
    MetaWebSocket *ws;
    
    if (!account || !account->ws_connection) return;
    
    ws = (MetaWebSocket *)account->ws_connection;
    
    meta_debug("Disconnecting WebSocket");
    
    /* Send MQTT DISCONNECT if connected */
    if (ws->state == META_WS_STATE_READY) {
        MetaMqttPacket *disconnect = meta_mqtt_packet_new(META_MQTT_DISCONNECT);
        gsize encoded_len;
        guint8 *encoded = meta_mqtt_packet_encode(disconnect, &encoded_len);
        if (encoded) {
            meta_websocket_send_raw(ws, encoded, encoded_len);
            g_free(encoded);
        }
        meta_mqtt_packet_free(disconnect);
    }
    
    /* Stop keepalive */
    meta_websocket_stop_keepalive(ws);
    
    /* Cancel reconnect */
    meta_websocket_cancel_reconnect(ws);
    
    /* Close SSL connection */
    if (ws->ssl_conn) {
        purple_ssl_close(ws->ssl_conn);
        ws->ssl_conn = NULL;
    }
    
    ws->state = META_WS_STATE_DISCONNECTED;
    
    /* Free the WebSocket */
    meta_websocket_free(ws);
    account->ws_connection = NULL;
}

gboolean meta_websocket_is_ready(MetaWebSocket *ws)
{
    return ws && ws->state == META_WS_STATE_READY;
}

MetaWebSocketState meta_websocket_get_state(MetaWebSocket *ws)
{
    return ws ? ws->state : META_WS_STATE_DISCONNECTED;
}

/* ============================================================
 * Data Processing
 * ============================================================ */

/* WebSocket frame parsing state */
typedef struct {
    gboolean fin;
    guint8 opcode;
    gboolean masked;
    guint64 payload_len;
    guint8 mask_key[4];
    gboolean header_complete;
    gsize header_size;
} WsFrameHeader;

static gboolean parse_ws_frame_header(const guint8 *data, gsize len,
                                       WsFrameHeader *header)
{
    gsize pos = 0;
    
    if (len < 2) return FALSE;
    
    header->fin = (data[0] & 0x80) != 0;
    header->opcode = data[0] & 0x0F;
    header->masked = (data[1] & 0x80) != 0;
    header->payload_len = data[1] & 0x7F;
    pos = 2;
    
    if (header->payload_len == 126) {
        if (len < 4) return FALSE;
        header->payload_len = (data[2] << 8) | data[3];
        pos = 4;
    } else if (header->payload_len == 127) {
        if (len < 10) return FALSE;
        header->payload_len = 0;
        for (int i = 0; i < 8; i++) {
            header->payload_len = (header->payload_len << 8) | data[2 + i];
        }
        pos = 10;
    }
    
    if (header->masked) {
        if (len < pos + 4) return FALSE;
        memcpy(header->mask_key, data + pos, 4);
        pos += 4;
    }
    
    header->header_size = pos;
    header->header_complete = TRUE;
    
    return TRUE;
}

static void unmask_payload(guint8 *data, gsize len, const guint8 *mask)
{
    for (gsize i = 0; i < len; i++) {
        data[i] ^= mask[i % 4];
    }
}

void meta_websocket_on_data(MetaWebSocket *ws, const guint8 *data, gsize len)
{
    /* Check if we're still waiting for HTTP upgrade response */
    if (ws->state == META_WS_STATE_CONNECTING) {
        /* Look for end of HTTP headers */
        const char *header_end = g_strstr_len((const char *)data, len, "\r\n\r\n");
        if (!header_end) {
            return;  /* Wait for complete headers */
        }
        
        /* Check for successful upgrade */
        if (g_strstr_len((const char *)data, len, "101")) {
            meta_debug("WebSocket upgrade successful");
            
            /* Remove HTTP response from buffer */
            gsize header_len = (header_end - (const char *)data) + 4;
            g_byte_array_remove_range(ws->read_buffer, 0, header_len);
            
            ws->state = META_WS_STATE_CONNECTED;
            meta_websocket_on_connected(ws);
            
            /* Process any remaining data */
            if (ws->read_buffer->len > 0) {
                meta_websocket_on_data(ws, ws->read_buffer->data, 
                                       ws->read_buffer->len);
            }
        } else {
            meta_error("WebSocket upgrade failed");
            meta_websocket_on_error(ws, "WebSocket upgrade rejected");
        }
        return;
    }
    
    /* Parse WebSocket frames */
    while (len > 0) {
        WsFrameHeader header;
        
        if (!parse_ws_frame_header(data, len, &header)) {
            break;  /* Incomplete header */
        }
        
        gsize frame_size = header.header_size + header.payload_len;
        if (len < frame_size) {
            break;  /* Incomplete frame */
        }
        
        /* Get payload */
        guint8 *payload = g_memdup2(data + header.header_size, header.payload_len);
        
        /* Unmask if needed */
        if (header.masked) {
            unmask_payload(payload, header.payload_len, header.mask_key);
        }
        
        /* Handle frame based on opcode */
        switch (header.opcode) {
            case 0x00:  /* Continuation */
            case 0x02:  /* Binary */
                /* MQTT data */
                meta_websocket_process_mqtt(ws, payload, header.payload_len);
                break;
                
            case 0x01:  /* Text */
                /* Shouldn't happen for MQTT, but handle anyway */
                meta_debug("Received text frame: %.*s", 
                          (int)header.payload_len, payload);
                break;
                
            case 0x08:  /* Close */
                meta_debug("Received close frame");
                meta_websocket_on_disconnected(ws, "Server closed connection");
                g_free(payload);
                return;
                
            case 0x09:  /* Ping */
                /* Send pong */
                meta_websocket_send_pong(ws, payload, header.payload_len);
                break;
                
            case 0x0A:  /* Pong */
                ws->last_pong_time = meta_get_timestamp_ms();
                break;
        }
        
        g_free(payload);
        
        /* Remove processed frame from buffer */
        g_byte_array_remove_range(ws->read_buffer, 0, frame_size);
        data = ws->read_buffer->data;
        len = ws->read_buffer->len;
    }
}

static void meta_websocket_process_mqtt(MetaWebSocket *ws, const guint8 *data,
                                         gsize len)
{
    gsize consumed;
    MetaMqttPacket *packet;
    
    while (len > 0) {
        packet = meta_mqtt_packet_decode(data, len, &consumed);
        if (!packet) {
            break;  /* Incomplete packet */
        }
        
        /* Handle packet type */
        switch (packet->type) {
            case META_MQTT_CONNACK:
                if (packet->payload && packet->payload->len >= 2) {
                    guint8 return_code = packet->payload->data[1];
                    if (return_code == 0) {
                        meta_debug("MQTT CONNACK: Connection accepted");
                        ws->state = META_WS_STATE_READY;
                        ws->account->state = META_STATE_CONNECTED;
                        
                        purple_connection_set_state(ws->account->pc,
                                                   PURPLE_CONNECTION_STATE_CONNECTED);
                        purple_connection_update_progress(ws->account->pc,
                                                         "Connected!", 4, 4);
                        
                        /* Subscribe to default topics */
                        meta_websocket_subscribe_defaults(ws);
                        
                        /* Start keepalive */
                        meta_websocket_start_keepalive(ws);
                        
                        /* Notify callback */
                        if (ws->on_connected) {
                            ws->on_connected(ws->account, TRUE, NULL,
                                           ws->callback_data);
                        }
                    } else {
                        meta_error("MQTT CONNACK: Connection refused (%d)", 
                                  return_code);
                        meta_websocket_on_error(ws, "MQTT connection refused");
                    }
                }
                break;
                
            case META_MQTT_PUBLISH:
                meta_debug("MQTT PUBLISH on topic: %s", 
                          packet->topic ? packet->topic : "(null)");
                if (packet->topic && packet->payload) {
                    meta_websocket_on_message(ws, packet->topic,
                                              packet->payload->data,
                                              packet->payload->len);
                }
                
                /* Send PUBACK if QoS > 0 */
                if (packet->qos > 0) {
                    MetaMqttPacket *puback = meta_mqtt_packet_new(META_MQTT_PUBACK);
                    puback->packet_id = packet->packet_id;
                    gsize enc_len;
                    guint8 *encoded = meta_mqtt_packet_encode(puback, &enc_len);
                    if (encoded) {
                        meta_websocket_send_raw(ws, encoded, enc_len);
                        g_free(encoded);
                    }
                    meta_mqtt_packet_free(puback);
                }
                break;
                
            case META_MQTT_PUBACK:
                /* Remove from pending ACKs */
                g_hash_table_remove(ws->pending_acks, 
                                   GINT_TO_POINTER(packet->packet_id));
                break;
                
            case META_MQTT_SUBACK:
                meta_debug("MQTT SUBACK received");
                break;
                
            case META_MQTT_PINGRESP:
                meta_debug("MQTT PINGRESP received");
                ws->last_pong_time = meta_get_timestamp_ms();
                break;
                
            default:
                meta_debug("Unhandled MQTT packet type: %d", packet->type);
        }
        
        meta_mqtt_packet_free(packet);
        data += consumed;
        len -= consumed;
    }
}

/* ============================================================
 * Event Handlers
 * ============================================================ */

void meta_websocket_on_connected(MetaWebSocket *ws)
{
    MetaMqttPacket *connect_pkt;
    gsize encoded_len;
    guint8 *encoded;
    
    meta_debug("WebSocket connected, sending MQTT CONNECT");
    
    ws->state = META_WS_STATE_AUTHENTICATING;
    
    purple_connection_update_progress(ws->account->pc, 
                                      "Authenticating with Meta...", 3, 4);
    
    /* Build and send MQTT CONNECT */
    connect_pkt = meta_mqtt_build_connect(ws);
    encoded = meta_mqtt_packet_encode(connect_pkt, &encoded_len);
    
    if (encoded) {
        meta_websocket_send_raw(ws, encoded, encoded_len);
        g_free(encoded);
    }
    
    meta_mqtt_packet_free(connect_pkt);
}

void meta_websocket_on_message(MetaWebSocket *ws, const char *topic,
                                const guint8 *payload, gsize len)
{
    meta_debug("Message on %s (%zu bytes)", topic, len);
    
    /* Try to decompress if it's zlib compressed */
    guint8 *decompressed = NULL;
    gsize decompressed_len = 0;
    
    if (len > 2 && payload[0] == 0x78) {
        /* Looks like zlib compressed */
        z_stream strm;
        memset(&strm, 0, sizeof(strm));
        
        if (inflateInit(&strm) == Z_OK) {
            decompressed = g_malloc(len * 10);  /* Estimate 10x compression */
            strm.next_in = (Bytef *)payload;
            strm.avail_in = len;
            strm.next_out = decompressed;
            strm.avail_out = len * 10;
            
            if (inflate(&strm, Z_FINISH) == Z_STREAM_END) {
                decompressed_len = strm.total_out;
                payload = decompressed;
                len = decompressed_len;
            } else {
                g_free(decompressed);
                decompressed = NULL;
            }
            
            inflateEnd(&strm);
        }
    }
    
    /* Parse the message based on topic */
    if (g_strcmp0(topic, META_TOPIC_MESSAGES) == 0 ||
        g_strcmp0(topic, META_TOPIC_MESSAGE_SYNC) == 0) {
        /* Parse message and deliver to libpurple */
        meta_websocket_handle_message_event(ws, payload, len);
    } else if (g_strcmp0(topic, META_TOPIC_TYPING) == 0) {
        meta_websocket_handle_typing_event(ws, payload, len);
    } else if (g_strcmp0(topic, META_TOPIC_PRESENCE) == 0) {
        meta_websocket_handle_presence_event(ws, payload, len);
    } else if (g_strcmp0(topic, META_TOPIC_READ_RECEIPTS) == 0) {
        meta_websocket_handle_read_receipt(ws, payload, len);
    }
    
    /* Call user callback */
    if (ws->on_message) {
        ws->on_message(ws->account, topic, payload, len, ws->callback_data);
    }
    
    g_free(decompressed);
}

static void meta_websocket_handle_message_event(MetaWebSocket *ws,
                                                 const guint8 *data, gsize len)
{
    JsonParser *parser;
    JsonObject *root;
    GError *error = NULL;
    
    /* Try to parse as JSON */
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, (const char *)data, len, &error)) {
        /* Might be Thrift-encoded */
        gchar *json_str = NULL;
        if (meta_websocket_parse_thrift(data, len, &json_str)) {
            json_parser_load_from_data(parser, json_str, -1, NULL);
            g_free(json_str);
        } else {
            g_error_free(error);
            g_object_unref(parser);
            return;
        }
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    if (!root) {
        g_object_unref(parser);
        return;
    }
    
    /* Extract message data */
    if (json_object_has_member(root, "deltas")) {
        JsonArray *deltas = json_object_get_array_member(root, "deltas");
        guint delta_count = json_array_get_length(deltas);
        
        for (guint i = 0; i < delta_count; i++) {
            JsonObject *delta = json_array_get_object_element(deltas, i);
            
            if (json_object_has_member(delta, "messageMetadata")) {
                JsonObject *metadata = json_object_get_object_member(delta, 
                                                                     "messageMetadata");
                const char *thread_key = NULL;
                const char *sender_id = NULL;
                const char *message_text = NULL;
                gint64 timestamp = 0;
                
                if (json_object_has_member(metadata, "threadKey")) {
                    JsonObject *tk = json_object_get_object_member(metadata, "threadKey");
                    if (json_object_has_member(tk, "otherUserFbId")) {
                        thread_key = json_object_get_string_member(tk, "otherUserFbId");
                    } else if (json_object_has_member(tk, "threadFbId")) {
                        thread_key = json_object_get_string_member(tk, "threadFbId");
                    }
                }
                
                if (json_object_has_member(metadata, "actorFbId")) {
                    sender_id = json_object_get_string_member(metadata, "actorFbId");
                }
                
                if (json_object_has_member(metadata, "timestamp")) {
                    timestamp = json_object_get_int_member(metadata, "timestamp");
                }
                
                if (json_object_has_member(delta, "body")) {
                    message_text = json_object_get_string_member(delta, "body");
                }
                
                /* Deliver message to libpurple */
                if (thread_key && sender_id && message_text) {
                    /* Check if it's from us */
                    if (g_strcmp0(sender_id, ws->account->user_id) != 0) {
                        purple_serv_got_im(ws->account->pc, sender_id, message_text,
                                          PURPLE_MESSAGE_RECV, timestamp / 1000);
                    }
                }
            }
        }
    }
    
    g_object_unref(parser);
}

static void meta_websocket_handle_typing_event(MetaWebSocket *ws,
                                                const guint8 *data, gsize len)
{
    JsonParser *parser;
    JsonObject *root;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, (const char *)data, len, NULL)) {
        g_object_unref(parser);
        return;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    if (root) {
        const char *sender = json_object_get_string_member_with_default(root, 
                                                                        "sender_fbid", NULL);
        gint64 state = json_object_get_int_member_with_default(root, "state", 0);
        
        if (sender) {
            purple_serv_got_typing(ws->account->pc, sender,
                                  state ? 5 : 0,
                                  state ? PURPLE_IM_TYPING : PURPLE_IM_NOT_TYPING);
        }
    }
    
    g_object_unref(parser);
}

static void meta_websocket_handle_presence_event(MetaWebSocket *ws,
                                                  const guint8 *data, gsize len)
{
    JsonParser *parser;
    JsonObject *root;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, (const char *)data, len, NULL)) {
        g_object_unref(parser);
        return;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    if (root && json_object_has_member(root, "list")) {
        JsonArray *list = json_object_get_array_member(root, "list");
        guint count = json_array_get_length(list);
        
        for (guint i = 0; i < count; i++) {
            JsonObject *presence = json_array_get_object_element(list, i);
            const char *user_id = json_object_get_string_member_with_default(
                                     presence, "u", NULL);
            gint64 active = json_object_get_int_member_with_default(
                               presence, "p", 0);
            
            if (user_id) {
                /* Update buddy presence */
                PurpleBuddy *buddy = purple_blist_find_buddy(ws->account->pa, user_id);
                if (buddy) {
                    purple_protocol_got_user_status(ws->account->pa, user_id,
                                                   active ? "available" : "offline",
                                                   NULL);
                }
            }
        }
    }
    
    g_object_unref(parser);
}

static void meta_websocket_handle_read_receipt(MetaWebSocket *ws,
                                                const guint8 *data, gsize len)
{
    /* Handle read receipts */
    meta_debug("Read receipt received (%zu bytes)", len);
}

void meta_websocket_on_disconnected(MetaWebSocket *ws, const char *reason)
{
    meta_debug("WebSocket disconnected: %s", reason ? reason : "unknown");
    
    ws->state = META_WS_STATE_DISCONNECTED;
    ws->account->state = META_STATE_DISCONNECTED;
    
    /* Stop keepalive */
    meta_websocket_stop_keepalive(ws);
    
    /* Close SSL if still open */
    if (ws->ssl_conn) {
        purple_ssl_close(ws->ssl_conn);
        ws->ssl_conn = NULL;
    }
    
    /* Notify callback */
    if (ws->on_disconnected) {
        ws->on_disconnected(ws->account, reason, ws->callback_data);
    }
    
    /* Schedule reconnect if not intentional */
    if (reason && !g_str_has_prefix(reason, "User")) {
        meta_websocket_schedule_reconnect(ws);
    }
}

void meta_websocket_on_error(MetaWebSocket *ws, const char *error)
{
    meta_error("WebSocket error: %s", error);
    
    ws->state = META_WS_STATE_ERROR;
    ws->account->state = META_STATE_ERROR;
    
    purple_connection_error(ws->account->pc,
                           PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                           error);
}

/* ============================================================
 * Topic Subscription
 * ============================================================ */

gboolean meta_websocket_subscribe(MetaWebSocket *ws, const char *topic)
{
    GList *topics = g_list_append(NULL, g_strdup(topic));
    MetaMqttPacket *subscribe;
    gsize encoded_len;
    guint8 *encoded;
    gboolean result = FALSE;
    
    subscribe = meta_mqtt_build_subscribe(ws, topics);
    encoded = meta_mqtt_packet_encode(subscribe, &encoded_len);
    
    if (encoded) {
        result = meta_websocket_send_raw(ws, encoded, encoded_len);
        g_free(encoded);
        
        if (result) {
            ws->subscriptions = g_list_append(ws->subscriptions, g_strdup(topic));
        }
    }
    
    meta_mqtt_packet_free(subscribe);
    g_list_free_full(topics, g_free);
    
    return result;
}

gboolean meta_websocket_unsubscribe(MetaWebSocket *ws, const char *topic)
{
    MetaMqttPacket *unsub = meta_mqtt_packet_new(META_MQTT_UNSUBSCRIBE);
    gsize encoded_len;
    guint8 *encoded;
    gboolean result = FALSE;
    
    unsub->packet_id = meta_ws_next_packet_id(ws);
    unsub->topic = g_strdup(topic);
    
    encoded = meta_mqtt_packet_encode(unsub, &encoded_len);
    if (encoded) {
        result = meta_websocket_send_raw(ws, encoded, encoded_len);
        g_free(encoded);
        
        if (result) {
            /* Remove from subscriptions list */
            GList *l = g_list_find_custom(ws->subscriptions, topic,
                                           (GCompareFunc)g_strcmp0);
            if (l) {
                g_free(l->data);
                ws->subscriptions = g_list_delete_link(ws->subscriptions, l);
            }
        }
    }
    
    meta_mqtt_packet_free(unsub);
    return result;
}

void meta_websocket_subscribe_defaults(MetaWebSocket *ws)
{
    meta_debug("Subscribing to default topics");
    
    if (ws->account->mode == META_SERVICE_INSTAGRAM) {
        meta_websocket_subscribe(ws, IG_TOPIC_DIRECT);
        meta_websocket_subscribe(ws, IG_TOPIC_MESSAGE_SYNC);
        meta_websocket_subscribe(ws, IG_TOPIC_REALTIME);
    } else {
        meta_websocket_subscribe(ws, META_TOPIC_MESSAGES);
        meta_websocket_subscribe(ws, META_TOPIC_MESSAGE_SYNC);
        meta_websocket_subscribe(ws, META_TOPIC_TYPING);
        meta_websocket_subscribe(ws, META_TOPIC_PRESENCE);
        meta_websocket_subscribe(ws, META_TOPIC_READ_RECEIPTS);
        meta_websocket_subscribe(ws, META_TOPIC_THREAD_UPDATES);
    }
}

/* ============================================================
 * Message Sending
 * ============================================================ */

static guint8 *meta_websocket_frame_message(const guint8 *data, gsize len,
                                             gsize *out_len, guint8 opcode)
{
    GByteArray *frame = g_byte_array_new();
    guint8 mask_key[4];
    
    /* Generate mask key */
    for (int i = 0; i < 4; i++) {
        mask_key[i] = g_random_int_range(0, 256);
    }
    
    /* First byte: FIN + opcode */
    guint8 first_byte = 0x80 | (opcode & 0x0F);
    g_byte_array_append(frame, &first_byte, 1);
    
    /* Second byte: mask bit + length */
    guint8 second_byte = 0x80;  /* Mask bit set */
    
    if (len < 126) {
        second_byte |= len;
        g_byte_array_append(frame, &second_byte, 1);
    } else if (len < 65536) {
        second_byte |= 126;
        g_byte_array_append(frame, &second_byte, 1);
        guint8 len_bytes[2] = { (len >> 8) & 0xFF, len & 0xFF };
        g_byte_array_append(frame, len_bytes, 2);
    } else {
        second_byte |= 127;
        g_byte_array_append(frame, &second_byte, 1);
        guint8 len_bytes[8];
        for (int i = 7; i >= 0; i--) {
            len_bytes[7 - i] = (len >> (i * 8)) & 0xFF;
        }
        g_byte_array_append(frame, len_bytes, 8);
    }
    
    /* Mask key */
    g_byte_array_append(frame, mask_key, 4);
    
    /* Masked payload */
    guint8 *masked_payload = g_memdup2(data, len);
    for (gsize i = 0; i < len; i++) {
        masked_payload[i] ^= mask_key[i % 4];
    }
    g_byte_array_append(frame, masked_payload, len);
    g_free(masked_payload);
    
    *out_len = frame->len;
    return g_byte_array_free(frame, FALSE);
}

gboolean meta_websocket_send_raw(MetaWebSocket *ws, const guint8 *data, gsize len)
{
    gsize frame_len;
    guint8 *frame;
    gssize written;
    
    if (!ws || ws->state < META_WS_STATE_CONNECTED || !ws->ssl_conn) {
        return FALSE;
    }
    
    /* Frame the message */
    frame = meta_websocket_frame_message(data, len, &frame_len, 0x02);  /* Binary */
    
    /* Write to SSL connection */
    written = purple_ssl_write(ws->ssl_conn, frame, frame_len);
    
    g_free(frame);
    
    if (written < 0) {
        meta_error("Failed to send WebSocket frame");
        return FALSE;
    }
    
    return TRUE;
}

gboolean meta_websocket_send_text(MetaWebSocket *ws, const char *text)
{
    gsize frame_len;
    guint8 *frame;
    gssize written;
    
    if (!ws || ws->state < META_WS_STATE_CONNECTED || !ws->ssl_conn) {
        return FALSE;
    }
    
    frame = meta_websocket_frame_message((const guint8 *)text, strlen(text),
                                          &frame_len, 0x01);  /* Text */
    
    written = purple_ssl_write(ws->ssl_conn, frame, frame_len);
    
    g_free(frame);
    
    return written >= 0;
}

static void meta_websocket_send_pong(MetaWebSocket *ws, const guint8 *data,
                                      gsize len)
{
    gsize frame_len;
    guint8 *frame;
    
    if (!ws || !ws->ssl_conn) return;
    
    frame = meta_websocket_frame_message(data, len, &frame_len, 0x0A);  /* Pong */
    purple_ssl_write(ws->ssl_conn, frame, frame_len);
    g_free(frame);
}

gboolean meta_websocket_publish(MetaWebSocket *ws, const char *topic,
                                 const guint8 *data, gsize len, guint8 qos)
{
    MetaMqttPacket *publish;
    gsize encoded_len;
    guint8 *encoded;
    gboolean result = FALSE;
    
    if (!ws || ws->state != META_WS_STATE_READY) {
        return FALSE;
    }
    
    publish = meta_mqtt_packet_new(META_MQTT_PUBLISH);
    publish->topic = g_strdup(topic);
    publish->payload = g_byte_array_new();
    g_byte_array_append(publish->payload, data, len);
    publish->qos = qos;
    
    if (qos > 0) {
        publish->packet_id = meta_ws_next_packet_id(ws);
    }
    
    encoded = meta_mqtt_packet_encode(publish, &encoded_len);
    if (encoded) {
        result = meta_websocket_send_raw(ws, encoded, encoded_len);
        g_free(encoded);
        
        /* Store for potential retransmit if QoS > 0 */
        if (result && qos > 0) {
            g_hash_table_insert(ws->pending_acks,
                               GINT_TO_POINTER(publish->packet_id),
                               meta_mqtt_packet_copy(publish));
        }
    }
    
    meta_mqtt_packet_free(publish);
    return result;
}

gboolean meta_websocket_publish_json(MetaWebSocket *ws, const char *topic,
                                      const char *json)
{
    return meta_websocket_publish(ws, topic, (const guint8 *)json, strlen(json), 1);
}

/* ============================================================
 * Keepalive
 * ============================================================ */

static gboolean meta_websocket_ping_timeout(gpointer data);
static gboolean meta_websocket_pong_timeout(gpointer data);

void meta_websocket_send_ping(MetaWebSocket *ws)
{
    MetaMqttPacket *ping;
    gsize encoded_len;
    guint8 *encoded;
    
    if (!ws || ws->state != META_WS_STATE_READY) {
        return;
    }
    
    ping = meta_mqtt_packet_new(META_MQTT_PINGREQ);
    encoded = meta_mqtt_packet_encode(ping, &encoded_len);
    
    if (encoded) {
        meta_websocket_send_raw(ws, encoded, encoded_len);
        g_free(encoded);
        
        ws->last_ping_time = meta_get_timestamp_ms();
        
        /* Set pong timeout */
        if (ws->pong_handle) {
            g_source_remove(ws->pong_handle);
        }
        ws->pong_handle = g_timeout_add_seconds(META_WS_PONG_TIMEOUT,
                                                 meta_websocket_pong_timeout, ws);
    }
    
    meta_mqtt_packet_free(ping);
}

static gboolean meta_websocket_ping_timeout(gpointer data)
{
    MetaWebSocket *ws = data;
    
    meta_websocket_send_ping(ws);
    
    return G_SOURCE_CONTINUE;
}

static gboolean meta_websocket_pong_timeout(gpointer data)
{
    MetaWebSocket *ws = data;
    
    ws->pong_handle = 0;
    
    /* Check if we received a pong */
    if (ws->last_pong_time < ws->last_ping_time) {
        meta_warning("Pong timeout, reconnecting...");
        meta_websocket_on_disconnected(ws, "Ping timeout");
    }
    
    return G_SOURCE_REMOVE;
}

void meta_websocket_start_keepalive(MetaWebSocket *ws)
{
    guint ping_interval;
    
    if (!ws) return;
    
    /* Stop existing timer */
    meta_websocket_stop_keepalive(ws);
    
    /* Get ping interval from config or use default */
    ping_interval = meta_config_get_ws_ping_interval();
    if (ping_interval == 0) {
        ping_interval = META_WS_PING_INTERVAL;
    }
    
    /* Start new timer */
    ws->ping_handle = g_timeout_add_seconds(ping_interval,
                                             meta_websocket_ping_timeout, ws);
    
    meta_debug("Keepalive started (interval: %ds)", ping_interval);
}

void meta_websocket_stop_keepalive(MetaWebSocket *ws)
{
    if (!ws) return;
    
    if (ws->ping_handle) {
        g_source_remove(ws->ping_handle);
        ws->ping_handle = 0;
    }
    
    if (ws->pong_handle) {
        g_source_remove(ws->pong_handle);
        ws->pong_handle = 0;
    }
}

/* ============================================================
 * Reconnection
 * ============================================================ */

static gboolean meta_websocket_reconnect_timeout(gpointer data);

void meta_websocket_schedule_reconnect(MetaWebSocket *ws)
{
    if (!ws) return;
    
    /* Cancel existing reconnect */
    meta_websocket_cancel_reconnect(ws);
    
    ws->state = META_WS_STATE_RECONNECTING;
    ws->reconnect_attempts++;
    
    /* Exponential backoff */
    ws->reconnect_delay = MIN(ws->reconnect_delay * 2, META_WS_MAX_RECONNECT_DELAY);
    
    meta_debug("Scheduling reconnect in %d seconds (attempt %d)",
               ws->reconnect_delay, ws->reconnect_attempts);
    
    ws->reconnect_handle = g_timeout_add_seconds(ws->reconnect_delay,
                                                  meta_websocket_reconnect_timeout,
                                                  ws);
}

static gboolean meta_websocket_reconnect_timeout(gpointer data)
{
    MetaWebSocket *ws = data;
    
    ws->reconnect_handle = 0;
    
    meta_debug("Attempting reconnect...");
    
    /* Try to reconnect */
    meta_websocket_connect(ws->account);
    
    return G_SOURCE_REMOVE;
}

void meta_websocket_cancel_reconnect(MetaWebSocket *ws)
{
    if (!ws) return;
    
    if (ws->reconnect_handle) {
        g_source_remove(ws->reconnect_handle);
        ws->reconnect_handle = 0;
    }
}

void meta_websocket_reset_reconnect(MetaWebSocket *ws)
{
    guint reconnect_delay;
    
    if (!ws) return;
    
    ws->reconnect_attempts = 0;
    
    /* Get reconnect delay from config or use default */
    reconnect_delay = meta_config_get_ws_reconnect_delay();
    ws->reconnect_delay = (reconnect_delay > 0) ? reconnect_delay : META_WS_RECONNECT_DELAY;
}

/* ============================================================
 * MQTT Packet Handling
 * ============================================================ */

MetaMqttPacket *meta_mqtt_packet_new(MetaMqttPacketType type)
{
    MetaMqttPacket *packet = g_new0(MetaMqttPacket, 1);
    packet->type = type;
    return packet;
}

void meta_mqtt_packet_free(MetaMqttPacket *packet)
{
    if (!packet) return;
    
    g_free(packet->topic);
    if (packet->payload) {
        g_byte_array_free(packet->payload, TRUE);
    }
    g_free(packet);
}

static MetaMqttPacket *meta_mqtt_packet_copy(MetaMqttPacket *packet)
{
    MetaMqttPacket *copy;
    
    if (!packet) return NULL;
    
    copy = meta_mqtt_packet_new(packet->type);
    copy->flags = packet->flags;
    copy->packet_id = packet->packet_id;
    copy->topic = g_strdup(packet->topic);
    copy->qos = packet->qos;
    copy->retain = packet->retain;
    copy->dup = packet->dup;
    
    if (packet->payload) {
        copy->payload = g_byte_array_new();
        g_byte_array_append(copy->payload, packet->payload->data, 
                           packet->payload->len);
    }
    
    return copy;
}

static void encode_remaining_length(GByteArray *buffer, guint32 length)
{
    do {
        guint8 byte = length % 128;
        length /= 128;
        if (length > 0) {
            byte |= 0x80;
        }
        g_byte_array_append(buffer, &byte, 1);
    } while (length > 0);
}

static guint32 decode_remaining_length(const guint8 *data, gsize len,
                                        gsize *bytes_consumed)
{
    guint32 value = 0;
    guint32 multiplier = 1;
    gsize pos = 0;
    
    do {
        if (pos >= len) {
            *bytes_consumed = 0;
            return 0;  /* Incomplete */
        }
        value += (data[pos] & 0x7F) * multiplier;
        multiplier *= 128;
    } while (data[pos++] & 0x80);
    
    *bytes_consumed = pos;
    return value;
}

guint8 *meta_mqtt_packet_encode(MetaMqttPacket *packet, gsize *out_len)
{
    GByteArray *buffer = g_byte_array_new();
    GByteArray *variable = g_byte_array_new();
    guint8 header;
    
    /* Build variable header and payload based on packet type */
    switch (packet->type) {
        case META_MQTT_CONNECT: {
            /* Protocol name */
            guint8 proto_len[] = { 0x00, 0x06 };
            g_byte_array_append(variable, proto_len, 2);
            g_byte_array_append(variable, (guint8 *)"MQIsdp", 6);
            
            /* Protocol level */
            guint8 level = 3;
            g_byte_array_append(variable, &level, 1);
            
            /* Connect flags */
            guint8 flags = 0x02;  /* Clean session */
            g_byte_array_append(variable, &flags, 1);
            
            /* Keep alive */
            guint8 keepalive[] = { 0x00, 0x3C };  /* 60 seconds */
            g_byte_array_append(variable, keepalive, 2);
            
            /* Client ID */
            if (packet->payload && packet->payload->len > 0) {
                guint16 id_len = packet->payload->len;
                guint8 id_len_bytes[] = { (id_len >> 8) & 0xFF, id_len & 0xFF };
                g_byte_array_append(variable, id_len_bytes, 2);
                g_byte_array_append(variable, packet->payload->data, 
                                   packet->payload->len);
            } else {
                guint8 empty_id[] = { 0x00, 0x00 };
                g_byte_array_append(variable, empty_id, 2);
            }
            break;
        }
        
        case META_MQTT_PUBLISH: {
            /* Topic name */
            if (packet->topic) {
                guint16 topic_len = strlen(packet->topic);
                guint8 topic_len_bytes[] = { (topic_len >> 8) & 0xFF, 
                                             topic_len & 0xFF };
                g_byte_array_append(variable, topic_len_bytes, 2);
                g_byte_array_append(variable, (guint8 *)packet->topic, topic_len);
            }
            
            /* Packet ID (if QoS > 0) */
            if (packet->qos > 0) {
                guint8 id_bytes[] = { (packet->packet_id >> 8) & 0xFF,
                                      packet->packet_id & 0xFF };
                g_byte_array_append(variable, id_bytes, 2);
            }
            
            /* Payload */
            if (packet->payload) {
                g_byte_array_append(variable, packet->payload->data,
                                   packet->payload->len);
            }
            break;
        }
        
        case META_MQTT_PUBACK:
        case META_MQTT_SUBACK:
        case META_MQTT_UNSUBACK: {
            guint8 id_bytes[] = { (packet->packet_id >> 8) & 0xFF,
                                  packet->packet_id & 0xFF };
            g_byte_array_append(variable, id_bytes, 2);
            break;
        }
        
        case META_MQTT_SUBSCRIBE: {
            /* Packet ID */
            guint8 id_bytes[] = { (packet->packet_id >> 8) & 0xFF,
                                  packet->packet_id & 0xFF };
            g_byte_array_append(variable, id_bytes, 2);
            
            /* Topic + QoS */
            if (packet->topic) {
                guint16 topic_len = strlen(packet->topic);
                guint8 topic_len_bytes[] = { (topic_len >> 8) & 0xFF,
                                             topic_len & 0xFF };
                g_byte_array_append(variable, topic_len_bytes, 2);
                g_byte_array_append(variable, (guint8 *)packet->topic, topic_len);
                guint8 qos = packet->qos;
                g_byte_array_append(variable, &qos, 1);
            }
            break;
        }
        
        case META_MQTT_UNSUBSCRIBE: {
            guint8 id_bytes[] = { (packet->packet_id >> 8) & 0xFF,
                                  packet->packet_id & 0xFF };
            g_byte_array_append(variable, id_bytes, 2);
            
            if (packet->topic) {
                guint16 topic_len = strlen(packet->topic);
                guint8 topic_len_bytes[] = { (topic_len >> 8) & 0xFF,
                                             topic_len & 0xFF };
                g_byte_array_append(variable, topic_len_bytes, 2);
                g_byte_array_append(variable, (guint8 *)packet->topic, topic_len);
            }
            break;
        }
        
        case META_MQTT_PINGREQ:
        case META_MQTT_PINGRESP:
        case META_MQTT_DISCONNECT:
            /* No variable header or payload */
            break;
            
        default:
            break;
    }
    
    /* Fixed header */
    header = (packet->type << 4) | (packet->flags & 0x0F);
    
    /* Special flags for PUBLISH */
    if (packet->type == META_MQTT_PUBLISH) {
        if (packet->dup) header |= 0x08;
        header |= (packet->qos & 0x03) << 1;
        if (packet->retain) header |= 0x01;
    }
    
    /* Special flags for SUBSCRIBE/UNSUBSCRIBE */
    if (packet->type == META_MQTT_SUBSCRIBE || 
        packet->type == META_MQTT_UNSUBSCRIBE) {
        header |= 0x02;  /* Reserved bit must be 1 */
    }
    
    g_byte_array_append(buffer, &header, 1);
    encode_remaining_length(buffer, variable->len);
    g_byte_array_append(buffer, variable->data, variable->len);
    
    g_byte_array_free(variable, TRUE);
    
    *out_len = buffer->len;
    return g_byte_array_free(buffer, FALSE);
}

MetaMqttPacket *meta_mqtt_packet_decode(const guint8 *data, gsize len,
                                         gsize *bytes_consumed)
{
    MetaMqttPacket *packet;
    gsize len_bytes;
    guint32 remaining_len;
    gsize pos;
    
    *bytes_consumed = 0;
    
    if (len < 2) {
        return NULL;  /* Need at least header + one length byte */
    }
    
    /* Decode remaining length */
    remaining_len = decode_remaining_length(data + 1, len - 1, &len_bytes);
    if (len_bytes == 0) {
        return NULL;  /* Incomplete length */
    }
    
    /* Check if we have complete packet */
    gsize total_len = 1 + len_bytes + remaining_len;
    if (len < total_len) {
        return NULL;  /* Incomplete packet */
    }
    
    packet = g_new0(MetaMqttPacket, 1);
    packet->type = (data[0] >> 4) & 0x0F;
    packet->flags = data[0] & 0x0F;
    
    pos = 1 + len_bytes;
    
    /* Decode based on packet type */
    switch (packet->type) {
        case META_MQTT_CONNACK:
            if (remaining_len >= 2) {
                packet->payload = g_byte_array_new();
                g_byte_array_append(packet->payload, data + pos, 2);
            }
            break;
            
        case META_MQTT_PUBLISH: {
            /* Decode flags */
            packet->dup = (packet->flags & 0x08) != 0;
            packet->qos = (packet->flags >> 1) & 0x03;
            packet->retain = (packet->flags & 0x01) != 0;
            
            /* Topic length */
            if (remaining_len >= 2) {
                guint16 topic_len = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                
                if (remaining_len >= 2 + topic