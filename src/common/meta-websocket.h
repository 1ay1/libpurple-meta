/**
 * meta-websocket.h
 * 
 * WebSocket connection handler for libpurple-meta
 * Manages persistent connections to Meta's messaging endpoints
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef META_WEBSOCKET_H
#define META_WEBSOCKET_H

#include <glib.h>
#include <purple.h>
#include "../prpl-meta.h"

/* WebSocket endpoints */
#define META_MQTT_ENDPOINT      "wss://edge-chat.facebook.com/chat"
#define META_MQTT_ORIGIN        "https://www.facebook.com"
#define INSTAGRAM_REALTIME_URL  "wss://edge-chat.instagram.com/chat"

/* Connection timeouts (in seconds) */
#define META_WS_CONNECT_TIMEOUT     30
#define META_WS_PING_INTERVAL       30
#define META_WS_PONG_TIMEOUT        10
#define META_WS_RECONNECT_DELAY     5
#define META_WS_MAX_RECONNECT_DELAY 300

/* WebSocket states */
typedef enum {
    META_WS_STATE_DISCONNECTED = 0,
    META_WS_STATE_CONNECTING,
    META_WS_STATE_CONNECTED,
    META_WS_STATE_AUTHENTICATING,
    META_WS_STATE_READY,
    META_WS_STATE_RECONNECTING,
    META_WS_STATE_ERROR
} MetaWebSocketState;

/* MQTT-like message types used by Meta */
typedef enum {
    META_MQTT_CONNECT     = 1,
    META_MQTT_CONNACK     = 2,
    META_MQTT_PUBLISH     = 3,
    META_MQTT_PUBACK      = 4,
    META_MQTT_SUBSCRIBE   = 8,
    META_MQTT_SUBACK      = 9,
    META_MQTT_UNSUBSCRIBE = 10,
    META_MQTT_UNSUBACK    = 11,
    META_MQTT_PINGREQ     = 12,
    META_MQTT_PINGRESP    = 13,
    META_MQTT_DISCONNECT  = 14
} MetaMqttPacketType;

/* Forward declarations */
typedef struct _MetaWebSocket MetaWebSocket;
typedef struct _MetaMqttPacket MetaMqttPacket;

/**
 * Callback types
 */
typedef void (*MetaWsConnectedCallback)(MetaAccount *account, gboolean success,
                                         const char *error, gpointer user_data);
typedef void (*MetaWsMessageCallback)(MetaAccount *account, const char *topic,
                                       const guint8 *data, gsize len,
                                       gpointer user_data);
typedef void (*MetaWsDisconnectedCallback)(MetaAccount *account, 
                                            const char *reason,
                                            gpointer user_data);

/**
 * MetaWebSocket - WebSocket connection state
 */
struct _MetaWebSocket {
    MetaAccount *account;           /* Parent account */
    MetaWebSocketState state;       /* Current connection state */
    
    /* Connection */
    PurpleSslConnection *ssl_conn;  /* SSL connection handle */
    GIOChannel *channel;            /* GLib IO channel */
    guint read_handle;              /* Read watch handle */
    guint write_handle;             /* Write watch handle */
    
    /* Alternative: libsoup WebSocket */
    gpointer soup_session;          /* SoupSession* */
    gpointer soup_websocket;        /* SoupWebsocketConnection* */
    
    /* Buffer management */
    GByteArray *read_buffer;        /* Incoming data buffer */
    GQueue *write_queue;            /* Outgoing message queue */
    gboolean write_pending;         /* Write in progress */
    
    /* MQTT state */
    guint16 next_packet_id;         /* Next MQTT packet ID */
    GHashTable *pending_acks;       /* Packets awaiting ACK */
    GList *subscriptions;           /* Active topic subscriptions */
    
    /* Keepalive */
    guint ping_handle;              /* Ping timer handle */
    guint pong_handle;              /* Pong timeout handle */
    gint64 last_ping_time;          /* Last ping sent timestamp */
    gint64 last_pong_time;          /* Last pong received timestamp */
    
    /* Reconnection */
    guint reconnect_handle;         /* Reconnect timer handle */
    guint reconnect_attempts;       /* Number of reconnect attempts */
    guint reconnect_delay;          /* Current reconnect delay */
    
    /* Callbacks */
    MetaWsConnectedCallback on_connected;
    MetaWsMessageCallback on_message;
    MetaWsDisconnectedCallback on_disconnected;
    gpointer callback_data;
    
    /* Sequence tracking */
    gint64 sequence_id;             /* Message sequence ID */
    gchar *sync_token;              /* Sync token for resuming */
};

/**
 * MetaMqttPacket - MQTT-like packet structure
 */
struct _MetaMqttPacket {
    MetaMqttPacketType type;        /* Packet type */
    guint8 flags;                   /* Packet flags */
    guint16 packet_id;              /* Packet identifier */
    gchar *topic;                   /* Topic name (for PUBLISH) */
    GByteArray *payload;            /* Packet payload */
    guint8 qos;                     /* Quality of Service level */
    gboolean retain;                /* Retain flag */
    gboolean dup;                   /* Duplicate flag */
};

/* ============================================================
 * Connection Management
 * ============================================================ */

/**
 * Create a new WebSocket connection handler
 * 
 * @param account The Meta account
 * @return New MetaWebSocket instance
 */
MetaWebSocket *meta_websocket_new(MetaAccount *account);

/**
 * Free a WebSocket connection handler
 * 
 * @param ws The WebSocket to free
 */
void meta_websocket_free(MetaWebSocket *ws);

/**
 * Connect to the WebSocket endpoint
 * 
 * @param account The Meta account to connect
 * @return TRUE if connection initiated successfully
 */
gboolean meta_websocket_connect(MetaAccount *account);

/**
 * Connect with callbacks
 * 
 * @param account The Meta account
 * @param on_connected Callback for connection result
 * @param on_message Callback for incoming messages
 * @param on_disconnected Callback for disconnection
 * @param user_data User data for callbacks
 * @return TRUE if connection initiated
 */
gboolean meta_websocket_connect_full(MetaAccount *account,
                                      MetaWsConnectedCallback on_connected,
                                      MetaWsMessageCallback on_message,
                                      MetaWsDisconnectedCallback on_disconnected,
                                      gpointer user_data);

/**
 * Disconnect the WebSocket
 * 
 * @param account The Meta account
 */
void meta_websocket_disconnect(MetaAccount *account);

/**
 * Check if WebSocket is connected and ready
 * 
 * @param ws The WebSocket
 * @return TRUE if ready to send/receive
 */
gboolean meta_websocket_is_ready(MetaWebSocket *ws);

/**
 * Get current WebSocket state
 * 
 * @param ws The WebSocket
 * @return Current state
 */
MetaWebSocketState meta_websocket_get_state(MetaWebSocket *ws);

/* ============================================================
 * Topic Subscription (MQTT-like)
 * ============================================================ */

/**
 * Subscribe to a topic
 * 
 * @param ws The WebSocket
 * @param topic Topic to subscribe to
 * @return TRUE if subscription request sent
 */
gboolean meta_websocket_subscribe(MetaWebSocket *ws, const char *topic);

/**
 * Unsubscribe from a topic
 * 
 * @param ws The WebSocket
 * @param topic Topic to unsubscribe from
 * @return TRUE if unsubscribe request sent
 */
gboolean meta_websocket_unsubscribe(MetaWebSocket *ws, const char *topic);

/**
 * Subscribe to standard Meta messaging topics
 * 
 * @param ws The WebSocket
 */
void meta_websocket_subscribe_defaults(MetaWebSocket *ws);

/* Default topics */
#define META_TOPIC_MESSAGES         "/t_ms"
#define META_TOPIC_MESSAGE_SYNC     "/messaging_events"
#define META_TOPIC_TYPING           "/typing"
#define META_TOPIC_PRESENCE         "/presence"
#define META_TOPIC_READ_RECEIPTS    "/t_rt"
#define META_TOPIC_THREAD_UPDATES   "/thread_updates"
#define META_TOPIC_NOTIFICATIONS    "/notifications"
#define META_TOPIC_LEGACY_WEB       "/legacy_web"

/* Instagram-specific topics */
#define IG_TOPIC_DIRECT             "/ig_direct"
#define IG_TOPIC_MESSAGE_SYNC       "/ig_message_sync"
#define IG_TOPIC_REALTIME           "/ig_realtime_sub"

/* ============================================================
 * Message Sending
 * ============================================================ */

/**
 * Publish a message to a topic
 * 
 * @param ws The WebSocket
 * @param topic Target topic
 * @param data Message data
 * @param len Data length
 * @param qos Quality of Service (0, 1, or 2)
 * @return TRUE if message queued for sending
 */
gboolean meta_websocket_publish(MetaWebSocket *ws, const char *topic,
                                 const guint8 *data, gsize len, guint8 qos);

/**
 * Publish a JSON message
 * 
 * @param ws The WebSocket
 * @param topic Target topic
 * @param json JSON string to send
 * @return TRUE if message queued
 */
gboolean meta_websocket_publish_json(MetaWebSocket *ws, const char *topic,
                                      const char *json);

/**
 * Send raw data over WebSocket
 * 
 * @param ws The WebSocket
 * @param data Data to send
 * @param len Data length
 * @return TRUE if data queued
 */
gboolean meta_websocket_send_raw(MetaWebSocket *ws, const guint8 *data, 
                                  gsize len);

/**
 * Send a text message over WebSocket
 * 
 * @param ws The WebSocket
 * @param text Text to send
 * @return TRUE if text queued
 */
gboolean meta_websocket_send_text(MetaWebSocket *ws, const char *text);

/* ============================================================
 * MQTT Packet Handling
 * ============================================================ */

/**
 * Create a new MQTT packet
 * 
 * @param type Packet type
 * @return New packet (caller must free)
 */
MetaMqttPacket *meta_mqtt_packet_new(MetaMqttPacketType type);

/**
 * Free an MQTT packet
 * 
 * @param packet Packet to free
 */
void meta_mqtt_packet_free(MetaMqttPacket *packet);

/**
 * Encode an MQTT packet to bytes
 * 
 * @param packet Packet to encode
 * @param out_len Output: length of encoded data
 * @return Encoded bytes (caller must free)
 */
guint8 *meta_mqtt_packet_encode(MetaMqttPacket *packet, gsize *out_len);

/**
 * Decode MQTT packet from bytes
 * 
 * @param data Input data
 * @param len Data length
 * @param bytes_consumed Output: bytes consumed
 * @return Decoded packet, or NULL if incomplete
 */
MetaMqttPacket *meta_mqtt_packet_decode(const guint8 *data, gsize len,
                                         gsize *bytes_consumed);

/**
 * Build MQTT CONNECT packet with Meta-specific fields
 * 
 * @param ws The WebSocket
 * @return CONNECT packet
 */
MetaMqttPacket *meta_mqtt_build_connect(MetaWebSocket *ws);

/**
 * Build MQTT SUBSCRIBE packet
 * 
 * @param ws The WebSocket
 * @param topics List of topics to subscribe
 * @return SUBSCRIBE packet
 */
MetaMqttPacket *meta_mqtt_build_subscribe(MetaWebSocket *ws, GList *topics);

/* ============================================================
 * Event Handlers (internal)
 * ============================================================ */

/**
 * Handle incoming WebSocket data
 * 
 * @param ws The WebSocket
 * @param data Received data
 * @param len Data length
 */
void meta_websocket_on_data(MetaWebSocket *ws, const guint8 *data, gsize len);

/**
 * Handle incoming MQTT message
 * 
 * @param ws The WebSocket
 * @param topic Message topic
 * @param payload Message payload
 * @param len Payload length
 */
void meta_websocket_on_message(MetaWebSocket *ws, const char *topic,
                                const guint8 *payload, gsize len);

/**
 * Handle connection established
 * 
 * @param ws The WebSocket
 */
void meta_websocket_on_connected(MetaWebSocket *ws);

/**
 * Handle connection closed
 * 
 * @param ws The WebSocket
 * @param reason Disconnect reason
 */
void meta_websocket_on_disconnected(MetaWebSocket *ws, const char *reason);

/**
 * Handle connection error
 * 
 * @param ws The WebSocket
 * @param error Error message
 */
void meta_websocket_on_error(MetaWebSocket *ws, const char *error);

/* ============================================================
 * Keepalive
 * ============================================================ */

/**
 * Send a ping/keepalive
 * 
 * @param ws The WebSocket
 */
void meta_websocket_send_ping(MetaWebSocket *ws);

/**
 * Start keepalive timer
 * 
 * @param ws The WebSocket
 */
void meta_websocket_start_keepalive(MetaWebSocket *ws);

/**
 * Stop keepalive timer
 * 
 * @param ws The WebSocket
 */
void meta_websocket_stop_keepalive(MetaWebSocket *ws);

/* ============================================================
 * Reconnection
 * ============================================================ */

/**
 * Schedule a reconnection attempt
 * 
 * @param ws The WebSocket
 */
void meta_websocket_schedule_reconnect(MetaWebSocket *ws);

/**
 * Cancel pending reconnection
 * 
 * @param ws The WebSocket
 */
void meta_websocket_cancel_reconnect(MetaWebSocket *ws);

/**
 * Reset reconnection state
 * 
 * @param ws The WebSocket
 */
void meta_websocket_reset_reconnect(MetaWebSocket *ws);

/* ============================================================
 * Utility Functions
 * ============================================================ */

/**
 * Get endpoint URL for service
 * 
 * @param mode Service mode (Messenger/Instagram)
 * @return WebSocket URL
 */
const char *meta_websocket_get_endpoint(MetaServiceMode mode);

/**
 * Generate a unique client session ID
 * 
 * @return Session ID (caller must free)
 */
gchar *meta_websocket_generate_session_id(void);

/**
 * Parse a thrift-encoded message (used by Meta)
 * 
 * @param data Thrift data
 * @param len Data length
 * @param out_json Output: parsed JSON (caller must free)
 * @return TRUE if parsing succeeded
 */
gboolean meta_websocket_parse_thrift(const guint8 *data, gsize len,
                                      gchar **out_json);

/**
 * Encode a message in thrift format
 * 
 * @param json JSON to encode
 * @param out_len Output: encoded length
 * @return Thrift bytes (caller must free)
 */
guint8 *meta_websocket_encode_thrift(const char *json, gsize *out_len);

#endif /* META_WEBSOCKET_H */