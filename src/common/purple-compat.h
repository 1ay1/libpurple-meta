/**
 * purple-compat.h
 * 
 * Compatibility layer for libpurple 2.x and 3.x
 * Abstracts away API differences between versions
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef PURPLE_COMPAT_H
#define PURPLE_COMPAT_H

#include <purple.h>

/* Detect purple version if not set by build system */
#ifndef PURPLE_VERSION
#  if defined(PURPLE_MAJOR_VERSION) && PURPLE_MAJOR_VERSION >= 3
#    define PURPLE_VERSION 3
#  else
#    define PURPLE_VERSION 2
#  endif
#endif

/* ============================================================
 * Connection State
 * ============================================================ */

#if PURPLE_VERSION == 2
#  define PURPLE_CONNECTION_STATE_CONNECTED    PURPLE_CONNECTED
#  define PURPLE_CONNECTION_STATE_CONNECTING   PURPLE_CONNECTING
#  define PURPLE_CONNECTION_STATE_DISCONNECTED PURPLE_DISCONNECTED
#endif

/* ============================================================
 * Typing State
 * ============================================================ */

#if PURPLE_VERSION == 2
#  define PURPLE_IM_TYPING      PURPLE_TYPING
#  define PURPLE_IM_NOT_TYPING  PURPLE_NOT_TYPING
#  define PURPLE_IM_TYPED       PURPLE_TYPED
   typedef PurpleTypingState PurpleIMTypingState;
#endif

/* ============================================================
 * Connection Error
 * ============================================================ */

#if PURPLE_VERSION == 2
/* libpurple 2 uses purple_connection_error_reason with 3 args */
#  define purple_connection_error(gc, reason_enum, message) \
       purple_connection_error_reason(gc, reason_enum, message)
#endif

/* ============================================================
 * Status Functions
 * ============================================================ */

#if PURPLE_VERSION == 2
#  define purple_status_get_status_type(status) \
       purple_status_get_type(status)
#endif

/* ============================================================
 * Conversation Helpers
 * ============================================================ */

#if PURPLE_VERSION == 2
#  define purple_serv_got_im(gc, who, msg, flags, time) \
       serv_got_im(gc, who, msg, flags, time)
#  define purple_serv_got_typing(gc, who, timeout, state) \
       serv_got_typing(gc, who, timeout, state)
#  define purple_serv_got_joined_chat(gc, id, name) \
       serv_got_joined_chat(gc, id, name)
#  define purple_conversations_find_chat(gc, id) \
       purple_find_chat(gc, id)
#endif

/* ============================================================
 * Buddy List
 * ============================================================ */

#if PURPLE_VERSION == 2
#  define purple_blist_find_buddy(account, name) \
       purple_find_buddy(account, name)
#  define purple_protocol_got_user_status(account, name, status_id, ...) \
       purple_prpl_got_user_status(account, name, status_id, ##__VA_ARGS__)
#endif

/* ============================================================
 * Chat Conversation
 * ============================================================ */

#if PURPLE_VERSION == 2
   typedef PurpleConversation PurpleChatConversation;
#  define purple_chat_conversation_add_user(conv, name, extra, flags, new_arrival) \
       purple_conv_chat_add_user(PURPLE_CONV_CHAT(conv), name, extra, flags, new_arrival)
#  define PURPLE_CHAT_USER_NONE PURPLE_CBFLAGS_NONE
#endif

/* ============================================================
 * Account Options
 * ============================================================ */

#if PURPLE_VERSION == 2
#  define purple_account_option_string_new_compat(text, pref_name, default_val) \
       purple_account_option_string_new(text, pref_name, default_val)
#  define purple_account_option_bool_new_compat(text, pref_name, default_val) \
       purple_account_option_bool_new(text, pref_name, default_val)
#  define purple_account_option_int_new_compat(text, pref_name, default_val) \
       purple_account_option_int_new(text, pref_name, default_val)
#else
#  define purple_account_option_string_new_compat purple_account_option_string_new
#  define purple_account_option_bool_new_compat   purple_account_option_bool_new
#  define purple_account_option_int_new_compat    purple_account_option_int_new
#endif

/* ============================================================
 * Message Flags
 * ============================================================ */

#if PURPLE_VERSION == 2
/* Already defined in libpurple 2 */
#else
/* libpurple 3 renamed some */
#  ifndef PURPLE_MESSAGE_RECV
#    define PURPLE_MESSAGE_RECV PURPLE_MESSAGE_RECEIVED
#  endif
#  ifndef PURPLE_MESSAGE_SEND  
#    define PURPLE_MESSAGE_SEND PURPLE_MESSAGE_SENT
#  endif
#endif

/* ============================================================
 * Value Types
 * ============================================================ */

#if PURPLE_VERSION == 2
/* libpurple 2 has its own type system */
#  ifndef PURPLE_TYPE_STRING
#    define PURPLE_TYPE_STRING G_TYPE_STRING
#  endif
#endif

/* ============================================================
 * Misc Helpers
 * ============================================================ */

/* Safe string handling */
static inline const char *purple_compat_normalize(PurpleAccount *account, const char *str)
{
    return purple_normalize(account, str);
}

/* Connection state helper */
static inline void purple_connection_set_state_compat(PurpleConnection *gc, int state)
{
    purple_connection_set_state(gc, state);
}

/* Get account from connection */
static inline PurpleAccount *purple_connection_get_account_compat(PurpleConnection *gc)
{
    return purple_connection_get_account(gc);
}

#endif /* PURPLE_COMPAT_H */