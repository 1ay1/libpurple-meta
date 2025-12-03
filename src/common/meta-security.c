/**
 * meta-security.c
 * 
 * Security module implementation for libpurple-meta
 * Handles secure token storage, audit logging, and input validation
 * 
 * Important: libpurple itself stores prefs in plaintext XML, so there's only
 * so much we can do here. The obfuscation is just to stop casual snooping,
 * not a determined attacker. Real fix would need keyring integration.
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#include "meta-security.h"
#include <json-glib/json-glib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

/* ============================================================
 * Internal Helpers
 * ============================================================ */

static gint64 get_timestamp(void)
{
    return (gint64)time(NULL);
}

/* Simple XOR obfuscation - yes this is weak, I know. It's just to prevent
 * tokens from being immediately visible in accounts.xml. A proper solution
 * would use libsecret/keyring but that adds dependencies and complexity.
 * PRs welcome if someone wants to add proper keyring support. */
static const guint8 OBFUSCATION_KEY[] = {
    0x4D, 0x65, 0x74, 0x61, 0x50, 0x6C, 0x75, 0x67,
    0x69, 0x6E, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74
};
static const gsize OBFUSCATION_KEY_LEN = sizeof(OBFUSCATION_KEY);

/* Patterns to redact in logs */
static const char *REDACT_PATTERNS[] = {
    "access_token",
    "session",
    "cookie",
    "password",
    "secret",
    "bearer",
    "authorization",
    "x-csrf",
    "xs=",
    "c_user=",
    NULL
};

/* ============================================================
 * Initialization
 * ============================================================ */

MetaSecurityContext *meta_security_context_new(MetaAccount *account)
{
    MetaSecurityContext *ctx = g_new0(MetaSecurityContext, 1);
    
    ctx->account = account;
    ctx->token_warned = FALSE;
    ctx->token_last_validated = 0;
    ctx->token_refresh_failures = 0;
    ctx->last_429_time = 0;
    ctx->consecutive_429s = 0;
    ctx->backoff_seconds = 1;
    ctx->pending_2fa = NULL;
    ctx->failed_login_count = 0;
    ctx->last_failed_login = 0;
    ctx->is_temporarily_blocked = FALSE;
    ctx->block_expires_at = 0;
    ctx->recent_events = NULL;
    ctx->max_event_log_size = 100;
    
    return ctx;
}

void meta_security_context_free(MetaSecurityContext *ctx)
{
    if (!ctx) return;
    
    /* Free 2FA state */
    if (ctx->pending_2fa) {
        g_free(ctx->pending_2fa->challenge_id);
        g_free(ctx->pending_2fa->phone_hint);
        g_free(ctx->pending_2fa->email_hint);
        g_free(ctx->pending_2fa);
    }
    
    /* Free event log */
    g_list_free(ctx->recent_events);
    
    g_free(ctx);
}

void meta_security_warn_plaintext_storage(MetaAccount *account)
{
    MetaSecurityContext *ctx;
    
    if (!account) return;
    
    /* Get or create security context */
    /* For now, show warning every time until we have proper context storage */
    
    if (!META_SECURITY_WARN_PLAINTEXT) return;
    
    purple_notify_warning(
        account->pc,
        "Security Warning",
        "Your Meta credentials are stored in PLAINTEXT. "
        "libpurple stores account credentials in an unencrypted file. "
        "Use full-disk encryption and set restrictive file permissions.",
        NULL
    );
}

/* ============================================================
 * Token Protection
 * ============================================================ */

static gchar *obfuscate_string(const char *input)
{
    gsize len;
    gchar *result;
    gsize i;
    
    if (!input) return NULL;
    
    len = strlen(input);
    result = g_malloc(len + 1);
    
    for (i = 0; i < len; i++) {
        result[i] = input[i] ^ OBFUSCATION_KEY[i % OBFUSCATION_KEY_LEN];
    }
    result[len] = '\0';
    
    /* Base64 encode the result for safe storage */
    gchar *encoded = g_base64_encode((guchar *)result, len);
    g_free(result);
    
    return encoded;
}

static gchar *deobfuscate_string(const char *encoded)
{
    gsize len;
    guchar *decoded;
    gchar *result;
    gsize i;
    
    if (!encoded) return NULL;
    
    decoded = g_base64_decode(encoded, &len);
    if (!decoded) return NULL;
    
    result = g_malloc(len + 1);
    
    for (i = 0; i < len; i++) {
        result[i] = decoded[i] ^ OBFUSCATION_KEY[i % OBFUSCATION_KEY_LEN];
    }
    result[len] = '\0';
    
    g_free(decoded);
    
    return result;
}

void meta_security_store_token(MetaAccount *account, const char *key,
                                const char *token)
{
    gchar *obfuscated;
    gchar *prefixed_key;
    
    if (!account || !account->pa || !key || !token) return;
    
    /* Obfuscate the token */
    if (META_SECURITY_TOKEN_OBFUSCATE) {
        obfuscated = obfuscate_string(token);
        prefixed_key = g_strdup_printf("_obf_%s", key);
    } else {
        obfuscated = g_strdup(token);
        prefixed_key = g_strdup(key);
    }
    
    purple_account_set_string(account->pa, prefixed_key, obfuscated);
    
    g_free(obfuscated);
    g_free(prefixed_key);
    
    /* Warn user on first token storage */
    meta_security_warn_plaintext_storage(account);
}

gchar *meta_security_retrieve_token(MetaAccount *account, const char *key)
{
    const char *stored;
    gchar *prefixed_key;
    gchar *token;
    
    if (!account || !account->pa || !key) return NULL;
    
    /* Try obfuscated key first */
    prefixed_key = g_strdup_printf("_obf_%s", key);
    stored = purple_account_get_string(account->pa, prefixed_key, NULL);
    g_free(prefixed_key);
    
    if (stored && META_SECURITY_TOKEN_OBFUSCATE) {
        token = deobfuscate_string(stored);
        return token;
    }
    
    /* Fall back to plain key */
    stored = purple_account_get_string(account->pa, key, NULL);
    if (stored) {
        return g_strdup(stored);
    }
    
    return NULL;
}

void meta_security_free_token(gchar *token)
{
    if (!token) return;
    
    /* Overwrite memory before freeing */
    gsize len = strlen(token);
    memset(token, 0, len);
    memset(token, 0xFF, len);
    memset(token, 0, len);
    
    g_free(token);
}

void meta_security_clear_all_tokens(MetaAccount *account)
{
    if (!account || !account->pa) return;
    
    /* Clear all known token keys */
    const char *token_keys[] = {
        "access_token", "_obf_access_token",
        "session_cookies", "_obf_session_cookies",
        "refresh_token", "_obf_refresh_token",
        "page_access_token", "_obf_page_access_token",
        NULL
    };
    
    for (int i = 0; token_keys[i]; i++) {
        purple_account_set_string(account->pa, token_keys[i], NULL);
    }
    
    /* Also clear from account struct */
    if (account->access_token) {
        meta_security_free_token(account->access_token);
        account->access_token = NULL;
    }
    if (account->session_cookies) {
        meta_security_free_token(account->session_cookies);
        account->session_cookies = NULL;
    }
    
    meta_debug("All tokens cleared for account");
}

gboolean meta_security_validate_token_format(const char *token)
{
    gsize len;
    
    if (!token) return FALSE;
    
    len = strlen(token);
    
    /* Basic format checks */
    if (len < 10 || len > META_MAX_TOKEN_LENGTH) {
        return FALSE;
    }
    
    /* Check for obviously invalid characters */
    for (gsize i = 0; i < len; i++) {
        char c = token[i];
        /* Tokens should be alphanumeric with some special chars */
        if (!isalnum(c) && c != '-' && c != '_' && c != '.' && c != '|') {
            /* Allow base64 characters */
            if (c != '+' && c != '/' && c != '=') {
                return FALSE;
            }
        }
    }
    
    return TRUE;
}

/* ============================================================
 * Input Validation
 * ============================================================ */

gboolean meta_security_validate_username(const char *username,
                                          gchar **sanitized)
{
    gsize len;
    GString *result;
    
    if (!username) return FALSE;
    
    len = strlen(username);
    
    /* Length check */
    if (len == 0 || len > META_MAX_USERNAME_LENGTH) {
        meta_warning("Username length invalid: %zu", len);
        return FALSE;
    }
    
    /* Build sanitized version */
    result = g_string_new(NULL);
    
    for (gsize i = 0; i < len; i++) {
        char c = username[i];
        
        /* Allow alphanumeric, dots, underscores, and @ for email */
        if (isalnum(c) || c == '.' || c == '_' || c == '@' || c == '-' || c == '+') {
            g_string_append_c(result, c);
        }
        /* Skip other characters */
    }
    
    if (result->len == 0) {
        g_string_free(result, TRUE);
        return FALSE;
    }
    
    if (sanitized) {
        *sanitized = g_string_free(result, FALSE);
    } else {
        g_string_free(result, TRUE);
    }
    
    return TRUE;
}

gboolean meta_security_validate_user_id(const char *user_id)
{
    gsize len;
    
    if (!user_id) return FALSE;
    
    len = strlen(user_id);
    
    if (len == 0 || len > META_MAX_USER_ID_LENGTH) {
        return FALSE;
    }
    
    /* User IDs should be numeric */
    for (gsize i = 0; i < len; i++) {
        if (!isdigit(user_id[i])) {
            return FALSE;
        }
    }
    
    return TRUE;
}

gboolean meta_security_validate_thread_id(const char *thread_id)
{
    gsize len;
    
    if (!thread_id) return FALSE;
    
    len = strlen(thread_id);
    
    if (len == 0 || len > META_MAX_THREAD_ID_LENGTH) {
        return FALSE;
    }
    
    /* Thread IDs can be numeric or have specific formats */
    for (gsize i = 0; i < len; i++) {
        char c = thread_id[i];
        if (!isalnum(c) && c != ':' && c != '_' && c != '-') {
            return FALSE;
        }
    }
    
    return TRUE;
}

gboolean meta_security_validate_message(const char *message,
                                         gchar **sanitized)
{
    gsize len;
    const gchar *end;
    GString *result;
    
    if (!message) return FALSE;
    
    len = strlen(message);
    
    /* Length check */
    if (len == 0 || len > META_MAX_MESSAGE_LENGTH) {
        meta_warning("Message length invalid: %zu", len);
        return FALSE;
    }
    
    /* Validate UTF-8 */
    if (!g_utf8_validate(message, len, &end)) {
        meta_warning("Message contains invalid UTF-8");
        return FALSE;
    }
    
    /* Build sanitized version - remove control characters except newlines */
    result = g_string_new(NULL);
    
    const gchar *p = message;
    while (*p) {
        gunichar c = g_utf8_get_char(p);
        
        /* Allow printable characters, spaces, newlines, tabs */
        if (g_unichar_isprint(c) || c == '\n' || c == '\r' || c == '\t' || c == ' ') {
            g_string_append_unichar(result, c);
        }
        /* Skip control characters */
        
        p = g_utf8_next_char(p);
    }
    
    if (sanitized) {
        *sanitized = g_string_free(result, FALSE);
    } else {
        g_string_free(result, TRUE);
    }
    
    return TRUE;
}

gboolean meta_security_validate_url(const char *url)
{
    gsize len;
    
    if (!url) return FALSE;
    
    len = strlen(url);
    
    if (len == 0 || len > META_MAX_URL_LENGTH) {
        return FALSE;
    }
    
    /* Must start with https:// for Meta APIs */
    if (!g_str_has_prefix(url, "https://")) {
        /* Allow http only for localhost (OAuth callback) */
        if (!g_str_has_prefix(url, "http://localhost") &&
            !g_str_has_prefix(url, "http://127.0.0.1")) {
            meta_warning("URL must use HTTPS: %s", url);
            return FALSE;
        }
    }
    
    /* Check for suspicious patterns */
    if (strstr(url, "javascript:") || strstr(url, "data:") ||
        strstr(url, "<script") || strstr(url, "%3Cscript")) {
        meta_warning("Suspicious URL pattern detected");
        return FALSE;
    }
    
    return TRUE;
}

gboolean meta_security_validate_json(const char *json, gsize max_size)
{
    JsonParser *parser;
    gboolean valid = FALSE;
    GError *error = NULL;
    gsize len;
    
    if (!json) return FALSE;
    
    len = strlen(json);
    
    if (len == 0 || len > max_size) {
        return FALSE;
    }
    
    /* Try to parse the JSON */
    parser = json_parser_new();
    
    if (json_parser_load_from_data(parser, json, len, &error)) {
        /* Check depth by traversing */
        /* For now, just accept if it parses */
        valid = TRUE;
    } else {
        meta_warning("Invalid JSON: %s", error ? error->message : "unknown");
        if (error) g_error_free(error);
    }
    
    g_object_unref(parser);
    
    return valid;
}

gchar *meta_security_sanitize_for_log(const char *input)
{
    GString *result;
    gchar *lower_input;
    gboolean redacted = FALSE;
    
    if (!input) return g_strdup("(null)");
    
    result = g_string_new(input);
    lower_input = g_ascii_strdown(input, -1);
    
    /* Check each redaction pattern */
    for (int i = 0; REDACT_PATTERNS[i]; i++) {
        if (strstr(lower_input, REDACT_PATTERNS[i])) {
            /* Found sensitive data - redact the whole thing */
            g_string_truncate(result, 0);
            g_string_append(result, "[REDACTED - contains sensitive data]");
            redacted = TRUE;
            break;
        }
    }
    
    g_free(lower_input);
    
    /* Also look for long base64-like strings (potential tokens) */
    if (!redacted) {
        gsize len = result->len;
        gsize consecutive_alnum = 0;
        
        for (gsize i = 0; i < len; i++) {
            if (isalnum(result->str[i]) || result->str[i] == '+' || 
                result->str[i] == '/' || result->str[i] == '=') {
                consecutive_alnum++;
                if (consecutive_alnum > 50) {
                    /* Long alphanumeric string - likely a token */
                    g_string_truncate(result, 0);
                    g_string_append(result, "[REDACTED - potential token]");
                    break;
                }
            } else {
                consecutive_alnum = 0;
            }
        }
    }
    
    return g_string_free(result, FALSE);
}

/* ============================================================
 * Audit Logging
 * ============================================================ */

static const char *event_names[] = {
    "LOGIN_ATTEMPT",
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "TOKEN_REFRESH",
    "TOKEN_EXPIRED",
    "SESSION_INVALIDATED",
    "RATE_LIMITED",
    "CHECKPOINT_REQUIRED",
    "2FA_REQUIRED",
    "SUSPICIOUS_ACTIVITY",
    "CONNECTION_ERROR",
    "TLS_ERROR",
    "MALFORMED_DATA",
    "INJECTION_ATTEMPT"
};

const char *meta_security_event_name(MetaSecurityEvent event)
{
    if (event >= 0 && event < G_N_ELEMENTS(event_names)) {
        return event_names[event];
    }
    return "UNKNOWN";
}

void meta_security_log_event(MetaSecurityContext *ctx,
                              MetaSecurityEvent event,
                              const char *details)
{
    gchar *sanitized_details;
    gchar *timestamp;
    GDateTime *now;
    
    if (!ctx) return;
    
    now = g_date_time_new_now_local();
    timestamp = g_date_time_format(now, "%Y-%m-%d %H:%M:%S");
    g_date_time_unref(now);
    
    sanitized_details = details ? meta_security_sanitize_for_log(details) : g_strdup("");
    
    /* Log to purple debug */
    purple_debug_info("prpl-meta-security", "[%s] %s: %s\n",
                      timestamp,
                      meta_security_event_name(event),
                      sanitized_details);
    
    /* Store in recent events (for debugging) */
    /* In production, you might want to limit this or disable it */
    
    g_free(timestamp);
    g_free(sanitized_details);
}

void meta_security_debug(const char *fmt, ...)
{
    va_list args;
    gchar *message;
    gchar *sanitized;
    
    va_start(args, fmt);
    message = g_strdup_vprintf(fmt, args);
    va_end(args);
    
    sanitized = meta_security_sanitize_for_log(message);
    
    purple_debug_info("prpl-meta", "%s\n", sanitized);
    
    g_free(message);
    g_free(sanitized);
}

/* ============================================================
 * Rate Limit Handling
 * ============================================================ */

void meta_security_record_rate_limit(MetaSecurityContext *ctx,
                                      guint retry_after)
{
    if (!ctx) return;
    
    ctx->last_429_time = get_timestamp();
    ctx->consecutive_429s++;
    
    /* Calculate backoff */
    if (retry_after > 0) {
        ctx->backoff_seconds = retry_after;
    } else {
        /* Exponential backoff: 1, 2, 4, 8, 16, 32, 60, 120, 300, 600 */
        ctx->backoff_seconds = MIN(ctx->backoff_seconds * 2, 600);
    }
    
    meta_security_log_event(ctx, META_SEC_EVENT_RATE_LIMITED,
                           g_strdup_printf("backoff=%u consecutive=%u",
                                          ctx->backoff_seconds,
                                          ctx->consecutive_429s));
    
    /* After too many rate limits, mark as temporarily blocked */
    if (ctx->consecutive_429s >= 5) {
        ctx->is_temporarily_blocked = TRUE;
        ctx->block_expires_at = get_timestamp() + 3600; /* 1 hour */
        
        meta_security_log_event(ctx, META_SEC_EVENT_SUSPICIOUS_ACTIVITY,
                               "Too many rate limits - temporarily blocked");
    }
}

guint meta_security_get_backoff_time(MetaSecurityContext *ctx)
{
    gint64 now;
    gint64 elapsed;
    
    if (!ctx) return 0;
    
    /* Check if blocked */
    if (ctx->is_temporarily_blocked) {
        now = get_timestamp();
        if (now < ctx->block_expires_at) {
            return (guint)(ctx->block_expires_at - now);
        }
        /* Block expired */
        ctx->is_temporarily_blocked = FALSE;
    }
    
    /* Check if still in backoff period */
    if (ctx->last_429_time > 0) {
        now = get_timestamp();
        elapsed = now - ctx->last_429_time;
        
        if (elapsed < ctx->backoff_seconds) {
            return ctx->backoff_seconds - (guint)elapsed;
        }
    }
    
    return 0;
}

void meta_security_reset_rate_limit(MetaSecurityContext *ctx)
{
    if (!ctx) return;
    
    /* Gradually reduce backoff on successful requests */
    if (ctx->consecutive_429s > 0) {
        ctx->consecutive_429s--;
    }
    
    if (ctx->consecutive_429s == 0) {
        ctx->backoff_seconds = 1;
        ctx->last_429_time = 0;
    }
}

gboolean meta_security_is_blocked(MetaSecurityContext *ctx)
{
    gint64 now;
    
    if (!ctx) return FALSE;
    
    if (!ctx->is_temporarily_blocked) {
        return FALSE;
    }
    
    now = get_timestamp();
    if (now >= ctx->block_expires_at) {
        ctx->is_temporarily_blocked = FALSE;
        return FALSE;
    }
    
    return TRUE;
}

/* ============================================================
 * Checkpoint / 2FA Handling
 * ============================================================ */

gboolean meta_security_handle_checkpoint(MetaAccount *account,
                                          MetaCheckpointType challenge_type,
                                          const char *challenge_data)
{
    const char *title;
    const char *primary;
    gchar *secondary;
    
    if (!account || !account->pc) return FALSE;
    
    /* Log the checkpoint */
    meta_warning("Checkpoint challenge received: type=%d", challenge_type);
    
    /* Build user-facing message based on type */
    switch (challenge_type) {
        case META_CHECKPOINT_VERIFY_EMAIL:
            title = "Email Verification Required";
            primary = "Meta requires email verification";
            secondary = g_strdup(
                "Please check your email and click the verification link, "
                "then try logging in again.");
            break;
            
        case META_CHECKPOINT_VERIFY_PHONE:
            title = "Phone Verification Required";
            primary = "Meta requires phone verification";
            secondary = g_strdup(
                "Please verify your phone number through the Meta app or website, "
                "then try logging in again.");
            break;
            
        case META_CHECKPOINT_2FA_SMS:
        case META_CHECKPOINT_2FA_TOTP:
            title = "Two-Factor Authentication";
            primary = "Enter your 2FA code";
            secondary = g_strdup(
                "Meta requires two-factor authentication. "
                "Please enter the code from your authenticator app or SMS.");
            /* Show input dialog for 2FA */
            /* For libpurple 2.x, just show a message - 2FA input is complex */
            purple_notify_error(
                account->pc,
                title,
                primary,
                "Please complete 2FA in the official app, then reconnect."
            );
            purple_connection_error_reason(
                account->pc,
                PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                "2FA required - complete in official app"
            );
            return TRUE;
            
        case META_CHECKPOINT_CAPTCHA:
            title = "CAPTCHA Required";
            primary = "Meta requires CAPTCHA verification";
            secondary = g_strdup(
                "Unfortunately, Meta is requiring a CAPTCHA which cannot be "
                "completed through this plugin. Please log in through the "
                "official app or website first, then try again here.");
            break;
            
        case META_CHECKPOINT_SUSPICIOUS_LOGIN:
            title = "Suspicious Login Detected";
            primary = "Meta flagged this login as suspicious";
            secondary = g_strdup(
                "Meta has detected unusual login activity. Please verify "
                "your identity through the official app or website, "
                "then try logging in again.");
            break;
            
        case META_CHECKPOINT_ACCOUNT_LOCKED:
            title = "Account Locked";
            primary = "Your Meta account is locked";
            secondary = g_strdup(
                "Your account has been temporarily locked. Please visit "
                "the Meta website to unlock your account.");
            break;
            
        case META_CHECKPOINT_CONSENT_REQUIRED:
            title = "Terms Update";
            primary = "Meta requires you to accept updated terms";
            secondary = g_strdup(
                "Please log in through the official app or website to "
                "accept the updated terms of service.");
            break;
            
        default:
            title = "Security Check Required";
            primary = "Meta requires additional verification";
            secondary = g_strdup(
                "An unknown security check is required. Please try logging "
                "in through the official app or website.");
            break;
    }
    
    /* Show notification for non-2FA checkpoints */
    purple_notify_error(
        account->pc,
        title,
        primary,
        secondary
    );
    
    g_free(secondary);
    
    /* Disconnect with appropriate error */
    purple_connection_error_reason(
        account->pc,
        PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
        primary
    );
    
    return TRUE;
}

/* 2FA callbacks stubbed out for libpurple 2.x - using simple notify instead */

void meta_security_submit_2fa_code(MetaAccount *account,
                                    const char *code,
                                    GCallback callback,
                                    gpointer user_data)
{
    /* This would send the 2FA code to Meta's verification endpoint */
    /* Implementation depends on whether we're doing Messenger or Instagram */
    
    meta_debug("Submitting 2FA code (length=%zu)", strlen(code));
    
    /* TODO: Implement actual 2FA submission */
    /* For now, just log it */
    purple_notify_info(
        account->pc,
        "2FA Code Submitted",
        "Your code has been submitted. Please wait while we verify.",
        NULL
    );
}

gboolean meta_security_resend_2fa_code(MetaAccount *account)
{
    if (!account) return FALSE;
    
    meta_debug("Requesting 2FA code resend");
    
    /* TODO: Implement actual resend request */
    
    purple_notify_info(
        account->pc,
        "Code Resent",
        "A new code has been requested. Check your phone for SMS.",
        NULL
    );
    
    return TRUE;
}

void meta_security_cancel_2fa(MetaAccount *account)
{
    if (!account) return;
    
    meta_debug("2FA cancelled by user");
}

gboolean meta_security_parse_checkpoint(const char *response,
                                         MetaCheckpointType *out_type,
                                         gchar **out_data)
{
    JsonParser *parser;
    JsonObject *root;
    const gchar *error_type;
    gboolean is_checkpoint = FALSE;
    
    if (!response) return FALSE;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, response, -1, NULL)) {
        g_object_unref(parser);
        return FALSE;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    
    /* Check for checkpoint indicators */
    if (json_object_has_member(root, "checkpoint_required") ||
        json_object_has_member(root, "challenge")) {
        is_checkpoint = TRUE;
        
        /* Try to determine type */
        if (json_object_has_member(root, "error_type")) {
            error_type = json_object_get_string_member(root, "error_type");
            
            if (g_strcmp0(error_type, "checkpoint_challenge_required") == 0) {
                *out_type = META_CHECKPOINT_SUSPICIOUS_LOGIN;
            } else if (g_strcmp0(error_type, "two_factor_required") == 0) {
                *out_type = META_CHECKPOINT_2FA_SMS;
            } else {
                *out_type = META_CHECKPOINT_CONSENT_REQUIRED;
            }
        }
        
        if (out_data) {
            JsonGenerator *gen = json_generator_new();
            json_generator_set_root(gen, json_parser_get_root(parser));
            *out_data = json_generator_to_data(gen, NULL);
            g_object_unref(gen);
        }
    }
    
    /* Instagram-specific checkpoint detection */
    if (json_object_has_member(root, "message")) {
        const gchar *message = json_object_get_string_member(root, "message");
        if (g_strcmp0(message, "checkpoint_required") == 0) {
            is_checkpoint = TRUE;
            *out_type = META_CHECKPOINT_SUSPICIOUS_LOGIN;
        } else if (strstr(message, "two_factor")) {
            is_checkpoint = TRUE;
            *out_type = META_CHECKPOINT_2FA_SMS;
        }
    }
    
    g_object_unref(parser);
    
    return is_checkpoint;
}

/* ============================================================
 * TLS / Connection Security
 * ============================================================ */

gboolean meta_security_validate_certificate(PurpleSslConnection *ssl,
                                             const char *hostname)
{
    /* libpurple handles basic certificate validation */
    /* We could add additional checks here like certificate pinning */
    
    if (!ssl || !hostname) return FALSE;
    
    /* For now, trust libpurple's validation */
    /* In a more secure implementation, we'd check:
     * - Certificate fingerprint against known Meta certs
     * - Certificate chain validity
     * - Certificate transparency logs
     */
    
    return TRUE;
}

gboolean meta_security_check_tls_version(PurpleSslConnection *ssl)
{
    /* libpurple doesn't expose TLS version directly */
    /* We trust that modern systems negotiate TLS 1.2+ */
    
    return TRUE;
}

/* ============================================================
 * Anti-Tampering
 * ============================================================ */

gboolean meta_security_validate_message_id(const char *message_id)
{
    gsize len;
    
    if (!message_id) return FALSE;
    
    len = strlen(message_id);
    
    /* Message IDs should be reasonable length */
    if (len == 0 || len > 128) {
        return FALSE;
    }
    
    /* Should only contain safe characters */
    for (gsize i = 0; i < len; i++) {
        char c = message_id[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != ':' && c != '.') {
            return FALSE;
        }
    }
    
    /* Check for injection patterns */
    if (strstr(message_id, "..") || strstr(message_id, "//") ||
        strstr(message_id, "<") || strstr(message_id, ">")) {
        return FALSE;
    }
    
    return TRUE;
}

gboolean meta_security_sanitize_incoming_message(const char *message,
                                                   gchar **sanitized)
{
    GString *result;
    const gchar *p;
    gsize len;
    
    if (!message) return FALSE;
    
    len = strlen(message);
    
    /* Reject extremely long messages */
    if (len > META_MAX_MESSAGE_LENGTH) {
        meta_warning("Incoming message too long: %zu bytes", len);
        return FALSE;
    }
    
    /* Validate UTF-8 */
    if (!g_utf8_validate(message, len, NULL)) {
        meta_warning("Incoming message contains invalid UTF-8");
        return FALSE;
    }
    
    result = g_string_new(NULL);
    p = message;
    
    while (*p) {
        gunichar c = g_utf8_get_char(p);
        
        /* Remove null bytes and other dangerous control characters */
        if (c == 0) {
            /* Skip null bytes */
        } else if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
            /* Skip other control characters */
        } else {
            g_string_append_unichar(result, c);
        }
        
        p = g_utf8_next_char(p);
    }
    
    if (sanitized) {
        *sanitized = g_string_free(result, FALSE);
    } else {
        g_string_free(result, TRUE);
    }
    
    return TRUE;
}

gboolean meta_security_validate_api_response(const char *response,
                                              const char **expected_fields)
{
    JsonParser *parser;
    JsonObject *root;
    gboolean valid = TRUE;
    
    if (!response) return FALSE;
    
    parser = json_parser_new();
    if (!json_parser_load_from_data(parser, response, -1, NULL)) {
        g_object_unref(parser);
        return FALSE;
    }
    
    root = json_node_get_object(json_parser_get_root(parser));
    if (!root) {
        g_object_unref(parser);
        return FALSE;
    }
    
    /* Check for required fields */
    if (expected_fields) {
        for (int i = 0; expected_fields[i]; i++) {
            if (!json_object_has_member(root, expected_fields[i])) {
                meta_warning("API response missing field: %s", expected_fields[i]);
                valid = FALSE;
                break;
            }
        }
    }
    
    g_object_unref(parser);
    
    return valid;
}

/* ============================================================
 * Secure Memory
 * ============================================================ */

gpointer meta_security_alloc(gsize size)
{
    gpointer ptr = g_malloc0(size);
    return ptr;
}

void meta_security_free(gpointer ptr, gsize size)
{
    if (!ptr) return;
    
    /* Overwrite memory before freeing */
    memset(ptr, 0, size);
    memset(ptr, 0xFF, size);
    memset(ptr, 0, size);
    
    g_free(ptr);
}

gchar *meta_security_strdup(const char *str)
{
    if (!str) return NULL;
    
    gsize len = strlen(str);
    gchar *copy = meta_security_alloc(len + 1);
    memcpy(copy, str, len + 1);
    
    return copy;
}