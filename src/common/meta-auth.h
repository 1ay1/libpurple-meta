/**
 * meta-auth.h
 * 
 * OAuth authentication module for libpurple-meta
 * Handles Meta (Facebook/Instagram) OAuth 2.0 flow and token management
 * 
 * Copyright (c) 2025
 * Licensed under GPL-3.0
 */

#ifndef META_AUTH_H
#define META_AUTH_H

#include <glib.h>
#include <purple.h>
#include "../prpl-meta.h"

/* OAuth configuration */
#define META_OAUTH_CLIENT_ID        "YOUR_META_APP_ID"
#define META_OAUTH_REDIRECT_URI     "https://localhost/oauth/callback"
#define META_OAUTH_SCOPE_MESSENGER  "pages_messaging,pages_read_engagement"
#define META_OAUTH_SCOPE_INSTAGRAM  "instagram_basic,instagram_manage_messages"

/* Meta API endpoints */
#define META_OAUTH_AUTH_URL         "https://www.facebook.com/v18.0/dialog/oauth"
#define META_OAUTH_TOKEN_URL        "https://graph.facebook.com/v18.0/oauth/access_token"
#define META_OAUTH_DEBUG_TOKEN_URL  "https://graph.facebook.com/debug_token"
#define META_GRAPH_API_BASE         "https://graph.facebook.com/v18.0"

/* Instagram API endpoints */
#define INSTAGRAM_API_BASE          "https://i.instagram.com/api/v1"
#define INSTAGRAM_GRAPH_API         "https://graph.instagram.com/v18.0"

/* Token refresh interval (in seconds) - refresh 5 minutes before expiry */
#define META_TOKEN_REFRESH_BUFFER   300

/* Forward declarations */
typedef struct _MetaAuthState MetaAuthState;
typedef struct _MetaOAuthToken MetaOAuthToken;

/**
 * Callback types for async auth operations
 */
typedef void (*MetaAuthCallback)(MetaAccount *account, gboolean success, 
                                  const char *error_message, gpointer user_data);
typedef void (*MetaTokenCallback)(MetaAccount *account, MetaOAuthToken *token,
                                   const char *error_message, gpointer user_data);

/**
 * MetaOAuthToken - Represents an OAuth access token
 */
struct _MetaOAuthToken {
    gchar *access_token;        /* The access token string */
    gchar *token_type;          /* Usually "bearer" */
    gint64 expires_at;          /* Unix timestamp when token expires */
    gchar *refresh_token;       /* Refresh token (if available) */
    gchar *user_id;             /* Associated user ID */
    
    /* Token permissions/scopes */
    GList *scopes;              /* List of granted scopes */
    
    /* For page tokens (Messenger) */
    gchar *page_id;             /* Facebook Page ID (for business messaging) */
    gchar *page_access_token;   /* Page-specific access token */
};

/**
 * MetaAuthState - Tracks the state of an authentication flow
 */
struct _MetaAuthState {
    MetaAccount *account;       /* Associated account */
    gchar *state;               /* OAuth state parameter for CSRF protection */
    gchar *code_verifier;       /* PKCE code verifier */
    gchar *code_challenge;      /* PKCE code challenge */
    guint timeout_handle;       /* Timeout for auth flow */
    MetaAuthCallback callback;  /* Completion callback */
    gpointer user_data;         /* User data for callback */
    
    /* HTTP server for OAuth callback (if using localhost redirect) */
    gpointer http_server;       /* GSocketService* */
    guint16 http_port;          /* Port for callback server */
};

/**
 * Cookie-based authentication for web scraping approach
 */
typedef struct {
    gchar *c_user;              /* User ID cookie */
    gchar *xs;                  /* Session cookie */
    gchar *datr;                /* Browser ID cookie */
    gchar *fr;                  /* Facebook tracking cookie */
    gchar *sb;                  /* Session binding cookie */
    gint64 expires_at;          /* When cookies expire */
} MetaSessionCookies;

/* ============================================================
 * OAuth Flow Functions
 * ============================================================ */

/**
 * Start the OAuth authentication flow
 * Opens browser for user to authenticate with Meta
 * 
 * @param account The Meta account to authenticate
 */
void meta_auth_start_oauth(MetaAccount *account);

/**
 * Start OAuth with callback
 * 
 * @param account The Meta account to authenticate
 * @param callback Function to call when auth completes
 * @param user_data Data to pass to callback
 */
void meta_auth_start_oauth_async(MetaAccount *account, 
                                  MetaAuthCallback callback,
                                  gpointer user_data);

/**
 * Handle OAuth callback (redirect with auth code)
 * 
 * @param state The MetaAuthState from the initial request
 * @param auth_code The authorization code from Meta
 * @param error Any error returned by Meta
 */
void meta_auth_handle_callback(MetaAuthState *state, 
                                const char *auth_code,
                                const char *error);

/**
 * Exchange authorization code for access token
 * 
 * @param account The Meta account
 * @param auth_code The authorization code to exchange
 * @param callback Function to call with token result
 * @param user_data Data to pass to callback
 */
void meta_auth_exchange_code(MetaAccount *account,
                              const char *auth_code,
                              MetaTokenCallback callback,
                              gpointer user_data);

/**
 * Cancel an in-progress OAuth flow
 * 
 * @param state The auth state to cancel
 */
void meta_auth_cancel(MetaAuthState *state);

/* ============================================================
 * Token Management Functions
 * ============================================================ */

/**
 * Validate an existing access token
 * Checks if the token is still valid and has required permissions
 * 
 * @param account The Meta account with token to validate
 * @return TRUE if token is valid, FALSE otherwise
 */
gboolean meta_auth_validate_token(MetaAccount *account);

/**
 * Async version of token validation
 * 
 * @param account The Meta account
 * @param callback Function to call with result
 * @param user_data Data to pass to callback
 */
void meta_auth_validate_token_async(MetaAccount *account,
                                     MetaAuthCallback callback,
                                     gpointer user_data);

/**
 * Refresh an access token using the refresh token
 * 
 * @param account The Meta account
 * @param callback Function to call with new token
 * @param user_data Data to pass to callback
 */
void meta_auth_refresh_token(MetaAccount *account,
                              MetaTokenCallback callback,
                              gpointer user_data);

/**
 * Store token in libpurple's secure storage
 * 
 * @param account The Meta account
 * @param token The token to store
 */
void meta_auth_store_token(MetaAccount *account, MetaOAuthToken *token);

/**
 * Load token from libpurple's secure storage
 * 
 * @param account The Meta account
 * @return The loaded token, or NULL if not found
 */
MetaOAuthToken *meta_auth_load_token(MetaAccount *account);

/**
 * Clear stored tokens
 * 
 * @param account The Meta account
 */
void meta_auth_clear_tokens(MetaAccount *account);

/**
 * Check if token needs refresh
 * 
 * @param token The token to check
 * @return TRUE if token should be refreshed
 */
gboolean meta_auth_token_needs_refresh(MetaOAuthToken *token);

/**
 * Get time until token expires
 * 
 * @param token The token to check
 * @return Seconds until expiry, or -1 if already expired
 */
gint64 meta_auth_token_expires_in(MetaOAuthToken *token);

/* ============================================================
 * Cookie-Based Authentication (for web scraping approach)
 * ============================================================ */

/**
 * Parse cookies from a cookie string (e.g., from browser)
 * 
 * @param cookie_string The raw cookie header string
 * @return Parsed session cookies
 */
MetaSessionCookies *meta_auth_parse_cookies(const char *cookie_string);

/**
 * Validate session cookies are still valid
 * 
 * @param account The Meta account
 * @param cookies The cookies to validate
 * @return TRUE if cookies are valid
 */
gboolean meta_auth_validate_cookies(MetaAccount *account,
                                     MetaSessionCookies *cookies);

/**
 * Store cookies in account settings
 * 
 * @param account The Meta account
 * @param cookies The cookies to store
 */
void meta_auth_store_cookies(MetaAccount *account,
                              MetaSessionCookies *cookies);

/**
 * Load cookies from account settings
 * 
 * @param account The Meta account
 * @return Loaded cookies, or NULL if not found
 */
MetaSessionCookies *meta_auth_load_cookies(MetaAccount *account);

/**
 * Get cookies formatted for HTTP header
 * 
 * @param cookies The session cookies
 * @return Cookie header string (caller must free)
 */
gchar *meta_auth_cookies_to_header(MetaSessionCookies *cookies);

/* ============================================================
 * Helper Functions
 * ============================================================ */

/**
 * Generate OAuth state parameter (for CSRF protection)
 * 
 * @return Random state string (caller must free)
 */
gchar *meta_auth_generate_state(void);

/**
 * Generate PKCE code verifier and challenge
 * 
 * @param verifier Output: code verifier (caller must free)
 * @param challenge Output: code challenge (caller must free)
 */
void meta_auth_generate_pkce(gchar **verifier, gchar **challenge);

/**
 * Build the OAuth authorization URL
 * 
 * @param account The Meta account
 * @param state The state parameter
 * @param code_challenge The PKCE challenge (optional, can be NULL)
 * @return Full authorization URL (caller must free)
 */
gchar *meta_auth_build_auth_url(MetaAccount *account,
                                 const char *state,
                                 const char *code_challenge);

/**
 * Open the authorization URL in user's browser
 * 
 * @param auth_url The URL to open
 * @return TRUE if browser was opened successfully
 */
gboolean meta_auth_open_browser(const char *auth_url);

/* ============================================================
 * Memory Management
 * ============================================================ */

/**
 * Free an OAuth token structure
 * 
 * @param token The token to free
 */
void meta_oauth_token_free(MetaOAuthToken *token);

/**
 * Free a session cookies structure
 * 
 * @param cookies The cookies to free
 */
void meta_session_cookies_free(MetaSessionCookies *cookies);

/**
 * Free an auth state structure
 * 
 * @param state The auth state to free
 */
void meta_auth_state_free(MetaAuthState *state);

/**
 * Duplicate an OAuth token
 * 
 * @param token The token to copy
 * @return New token copy (caller must free)
 */
MetaOAuthToken *meta_oauth_token_copy(MetaOAuthToken *token);

#endif /* META_AUTH_H */