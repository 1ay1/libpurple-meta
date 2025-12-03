/**
 * meta-security.h
 * 
 * Security module for libpurple-meta
 * Handles secure token storage, audit logging, and input validation
 * 
 * ⚠️  SECURITY NOTICE ⚠️
 * libpurple stores account settings in PLAINTEXT files!
 * - Linux: ~/.purple/accounts.xml
 * - Windows: %APPDATA%\.purple\accounts.xml
 * 
 * Access tokens stored here are NOT encrypted. Anyone with file access
 * can read your Meta credentials. This plugin warns users about this.
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef META_SECURITY_H
#define META_SECURITY_H

#include <glib.h>
#include <purple.h>
#include "../prpl-meta.h"

/* Security configuration */
#define META_SECURITY_TOKEN_OBFUSCATE     TRUE   /* Basic obfuscation (not encryption!) */
#define META_SECURITY_LOG_SENSITIVE       FALSE  /* NEVER enable in production */
#define META_SECURITY_WARN_PLAINTEXT      TRUE   /* Warn users about plaintext storage */
#define META_SECURITY_MAX_TOKEN_AGE       86400  /* Force re-auth after 24 hours */

/* Sensitive data patterns to redact in logs */
#define META_REDACT_PATTERN_TOKEN         "access_token"
#define META_REDACT_PATTERN_SESSION       "session"
#define META_REDACT_PATTERN_COOKIE        "cookie"
#define META_REDACT_PATTERN_PASSWORD      "password"
#define META_REDACT_PATTERN_SECRET        "secret"

/* Input validation limits */
#define META_MAX_USERNAME_LENGTH          256
#define META_MAX_MESSAGE_LENGTH           20000
#define META_MAX_THREAD_ID_LENGTH         128
#define META_MAX_USER_ID_LENGTH           64
#define META_MAX_TOKEN_LENGTH             2048
#define META_MAX_URL_LENGTH               4096
#define META_MAX_JSON_DEPTH               32

/* Security event types for audit logging */
typedef enum {
    META_SEC_EVENT_LOGIN_ATTEMPT = 0,
    META_SEC_EVENT_LOGIN_SUCCESS,
    META_SEC_EVENT_LOGIN_FAILURE,
    META_SEC_EVENT_TOKEN_REFRESH,
    META_SEC_EVENT_TOKEN_EXPIRED,
    META_SEC_EVENT_SESSION_INVALIDATED,
    META_SEC_EVENT_RATE_LIMITED,
    META_SEC_EVENT_CHECKPOINT_REQUIRED,
    META_SEC_EVENT_2FA_REQUIRED,
    META_SEC_EVENT_SUSPICIOUS_ACTIVITY,
    META_SEC_EVENT_CONNECTION_ERROR,
    META_SEC_EVENT_TLS_ERROR,
    META_SEC_EVENT_MALFORMED_DATA,
    META_SEC_EVENT_INJECTION_ATTEMPT
} MetaSecurityEvent;

/* Checkpoint challenge types (Instagram/Facebook security checks) */
typedef enum {
    META_CHECKPOINT_NONE = 0,
    META_CHECKPOINT_VERIFY_EMAIL,
    META_CHECKPOINT_VERIFY_PHONE,
    META_CHECKPOINT_2FA_SMS,
    META_CHECKPOINT_2FA_TOTP,
    META_CHECKPOINT_CAPTCHA,
    META_CHECKPOINT_SUSPICIOUS_LOGIN,
    META_CHECKPOINT_ACCOUNT_LOCKED,
    META_CHECKPOINT_CONSENT_REQUIRED
} MetaCheckpointType;

/* 2FA state */
typedef struct _Meta2FAState {
    MetaCheckpointType type;
    gchar *challenge_id;
    gchar *phone_hint;          /* Last 4 digits of phone */
    gchar *email_hint;          /* Masked email */
    gint64 expires_at;
    guint retry_count;
    guint max_retries;
} Meta2FAState;

/* Security context for an account */
typedef struct _MetaSecurityContext {
    MetaAccount *account;
    
    /* Token security */
    gboolean token_warned;          /* User has been warned about plaintext */
    gint64 token_last_validated;    /* Last validation timestamp */
    guint token_refresh_failures;   /* Consecutive refresh failures */
    
    /* Rate limit tracking */
    gint64 last_429_time;           /* Last HTTP 429 received */
    guint consecutive_429s;         /* Count of consecutive 429s */
    guint backoff_seconds;          /* Current backoff delay */
    
    /* Checkpoint/2FA state */
    Meta2FAState *pending_2fa;
    
    /* Suspicious activity tracking */
    guint failed_login_count;
    gint64 last_failed_login;
    gboolean is_temporarily_blocked;
    gint64 block_expires_at;
    
    /* Audit log */
    GList *recent_events;           /* Recent MetaSecurityEvent entries */
    guint max_event_log_size;
} MetaSecurityContext;

/* ============================================================
 * Initialization
 * ============================================================ */

/**
 * Initialize security context for an account
 * 
 * @param account The Meta account
 * @return New security context
 */
MetaSecurityContext *meta_security_context_new(MetaAccount *account);

/**
 * Free security context
 * 
 * @param ctx The security context to free
 */
void meta_security_context_free(MetaSecurityContext *ctx);

/**
 * Show plaintext storage warning to user (once per account)
 * 
 * @param account The Meta account
 */
void meta_security_warn_plaintext_storage(MetaAccount *account);

/* ============================================================
 * Token Protection
 * ============================================================ */

/**
 * Store a token with basic obfuscation
 * NOTE: This is NOT encryption! It only prevents casual viewing.
 * 
 * @param account The Meta account
 * @param key Setting key
 * @param token The token to store
 */
void meta_security_store_token(MetaAccount *account, const char *key,
                                const char *token);

/**
 * Retrieve an obfuscated token
 * 
 * @param account The Meta account
 * @param key Setting key
 * @return Deobfuscated token (caller must free with meta_security_free_token)
 */
gchar *meta_security_retrieve_token(MetaAccount *account, const char *key);

/**
 * Securely free a token from memory
 * Overwrites memory before freeing to prevent memory dumps
 * 
 * @param token The token to free
 */
void meta_security_free_token(gchar *token);

/**
 * Clear all stored tokens for an account
 * 
 * @param account The Meta account
 */
void meta_security_clear_all_tokens(MetaAccount *account);

/**
 * Check if token appears compromised or suspicious
 * 
 * @param token The token to check
 * @return TRUE if token looks valid, FALSE if suspicious
 */
gboolean meta_security_validate_token_format(const char *token);

/* ============================================================
 * Input Validation
 * ============================================================ */

/**
 * Validate and sanitize a username
 * 
 * @param username Input username
 * @param sanitized Output: sanitized username (caller must free)
 * @return TRUE if valid, FALSE if rejected
 */
gboolean meta_security_validate_username(const char *username,
                                          gchar **sanitized);

/**
 * Validate a user ID (numeric string)
 * 
 * @param user_id The user ID to validate
 * @return TRUE if valid
 */
gboolean meta_security_validate_user_id(const char *user_id);

/**
 * Validate a thread ID
 * 
 * @param thread_id The thread ID to validate
 * @return TRUE if valid
 */
gboolean meta_security_validate_thread_id(const char *thread_id);

/**
 * Validate a message before sending
 * Checks length, encoding, and potentially malicious content
 * 
 * @param message The message to validate
 * @param sanitized Output: sanitized message (caller must free)
 * @return TRUE if valid
 */
gboolean meta_security_validate_message(const char *message,
                                         gchar **sanitized);

/**
 * Validate a URL
 * 
 * @param url The URL to validate
 * @return TRUE if valid and safe
 */
gboolean meta_security_validate_url(const char *url);

/**
 * Validate JSON structure
 * Checks depth, size, and structure
 * 
 * @param json The JSON string to validate
 * @param max_size Maximum allowed size
 * @return TRUE if valid
 */
gboolean meta_security_validate_json(const char *json, gsize max_size);

/**
 * Sanitize a string for safe logging
 * Redacts sensitive patterns
 * 
 * @param input The string to sanitize
 * @return Sanitized string (caller must free)
 */
gchar *meta_security_sanitize_for_log(const char *input);

/* ============================================================
 * Audit Logging
 * ============================================================ */

/**
 * Log a security event
 * 
 * @param ctx Security context
 * @param event Event type
 * @param details Optional details (will be sanitized)
 */
void meta_security_log_event(MetaSecurityContext *ctx,
                              MetaSecurityEvent event,
                              const char *details);

/**
 * Get human-readable event name
 * 
 * @param event The event type
 * @return Event name string
 */
const char *meta_security_event_name(MetaSecurityEvent event);

/**
 * Debug log with automatic sensitive data redaction
 * Use this instead of meta_debug() for potentially sensitive data
 * 
 * @param fmt Format string
 * @param ... Arguments
 */
void meta_security_debug(const char *fmt, ...) G_GNUC_PRINTF(1, 2);

/* ============================================================
 * Rate Limit Handling
 * ============================================================ */

/**
 * Record an HTTP 429 (rate limit) response
 * 
 * @param ctx Security context
 * @param retry_after Retry-After header value (0 if not present)
 */
void meta_security_record_rate_limit(MetaSecurityContext *ctx,
                                      guint retry_after);

/**
 * Check if we should back off due to rate limiting
 * 
 * @param ctx Security context
 * @return Seconds to wait, or 0 if OK to proceed
 */
guint meta_security_get_backoff_time(MetaSecurityContext *ctx);

/**
 * Reset rate limit state after successful request
 * 
 * @param ctx Security context
 */
void meta_security_reset_rate_limit(MetaSecurityContext *ctx);

/**
 * Check if account is temporarily blocked
 * 
 * @param ctx Security context
 * @return TRUE if blocked
 */
gboolean meta_security_is_blocked(MetaSecurityContext *ctx);

/* ============================================================
 * Checkpoint / 2FA Handling
 * ============================================================ */

/**
 * Handle a checkpoint challenge from Meta
 * 
 * @param account The Meta account
 * @param challenge_type Type of challenge
 * @param challenge_data JSON data from Meta
 * @return TRUE if challenge UI was shown
 */
gboolean meta_security_handle_checkpoint(MetaAccount *account,
                                          MetaCheckpointType challenge_type,
                                          const char *challenge_data);

/**
 * Submit 2FA code
 * 
 * @param account The Meta account
 * @param code The 2FA code entered by user
 * @param callback Completion callback
 * @param user_data User data for callback
 */
void meta_security_submit_2fa_code(MetaAccount *account,
                                    const char *code,
                                    GCallback callback,
                                    gpointer user_data);

/**
 * Request 2FA code resend (SMS)
 * 
 * @param account The Meta account
 * @return TRUE if resend was requested
 */
gboolean meta_security_resend_2fa_code(MetaAccount *account);

/**
 * Cancel pending 2FA challenge
 * 
 * @param account The Meta account
 */
void meta_security_cancel_2fa(MetaAccount *account);

/**
 * Parse checkpoint response from Meta API
 * 
 * @param response API response
 * @param out_type Output: checkpoint type
 * @param out_data Output: challenge data (caller must free)
 * @return TRUE if checkpoint was detected
 */
gboolean meta_security_parse_checkpoint(const char *response,
                                         MetaCheckpointType *out_type,
                                         gchar **out_data);

/* ============================================================
 * TLS / Connection Security
 * ============================================================ */

/**
 * Validate TLS certificate (additional checks beyond libpurple)
 * 
 * @param ssl SSL connection
 * @param hostname Expected hostname
 * @return TRUE if certificate is valid
 */
gboolean meta_security_validate_certificate(PurpleSslConnection *ssl,
                                             const char *hostname);

/**
 * Check if connection is using secure TLS version
 * 
 * @param ssl SSL connection
 * @return TRUE if TLS 1.2+
 */
gboolean meta_security_check_tls_version(PurpleSslConnection *ssl);

/* ============================================================
 * Anti-Tampering
 * ============================================================ */

/**
 * Validate message ID format before injecting into libpurple
 * Prevents injection attacks via malformed IDs
 * 
 * @param message_id The message ID to validate
 * @return TRUE if safe to use
 */
gboolean meta_security_validate_message_id(const char *message_id);

/**
 * Validate incoming message before displaying
 * Checks for script injection, malformed UTF-8, etc.
 * 
 * @param message Incoming message
 * @param sanitized Output: sanitized message (caller must free)
 * @return TRUE if message is safe
 */
gboolean meta_security_sanitize_incoming_message(const char *message,
                                                   gchar **sanitized);

/**
 * Validate API response structure
 * Guards against malformed JSON that could crash the plugin
 * 
 * @param response API response
 * @param expected_fields NULL-terminated list of required fields
 * @return TRUE if response has expected structure
 */
gboolean meta_security_validate_api_response(const char *response,
                                              const char **expected_fields);

/* ============================================================
 * Secure Memory
 * ============================================================ */

/**
 * Allocate secure memory that will be zeroed on free
 * 
 * @param size Bytes to allocate
 * @return Allocated memory
 */
gpointer meta_security_alloc(gsize size);

/**
 * Free secure memory (zeros before freeing)
 * 
 * @param ptr Memory to free
 * @param size Size of allocation
 */
void meta_security_free(gpointer ptr, gsize size);

/**
 * Secure string duplication
 * 
 * @param str String to duplicate
 * @return Duplicated string in secure memory
 */
gchar *meta_security_strdup(const char *str);

/* ============================================================
 * Utility Macros
 * ============================================================ */

/* Log security events */
#define meta_sec_log(ctx, event, details) \
    meta_security_log_event(ctx, event, details)

/* Validate or return FALSE */
#define META_VALIDATE_OR_FAIL(condition, msg) \
    do { \
        if (!(condition)) { \
            meta_warning("Validation failed: %s", msg); \
            return FALSE; \
        } \
    } while (0)

/* Validate or return NULL */
#define META_VALIDATE_OR_NULL(condition, msg) \
    do { \
        if (!(condition)) { \
            meta_warning("Validation failed: %s", msg); \
            return NULL; \
        } \
    } while (0)

/* Safe string length check */
#define META_SAFE_STRLEN(s) ((s) ? strlen(s) : 0)

/* Check string is non-empty and within limits */
#define META_VALID_STRING(s, max_len) \
    ((s) != NULL && (s)[0] != '\0' && strlen(s) <= (max_len))

#endif /* META_SECURITY_H */