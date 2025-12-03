# libpurple-meta Configuration Guide

This guide explains how to configure the libpurple-meta plugin for use with Facebook Messenger and Instagram Direct Messages.

## Table of Contents

1. [Overview](#overview)
2. [Configuration File Locations](#configuration-file-locations)
3. [Basic Setup](#basic-setup)
4. [Configuration Reference](#configuration-reference)
5. [Instagram Setup](#instagram-setup)
6. [Messenger Setup](#messenger-setup)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Configuration](#advanced-configuration)

---

## Overview

libpurple-meta can be configured in two ways:

### 1. Account Settings UI (Recommended for most users)

Most important settings are now available directly in Pidgin's account settings dialog. When you add or modify a Meta account, click the **Advanced** tab to access:

- **Service selection** (Messenger, Instagram, or both)
- **Meta App ID** (required for Messenger OAuth)
- **Feature toggles** (presence, typing indicators, reactions, etc.)
- **Rate limits** (to avoid bans)
- **Instagram app version** (for compatibility updates)
- **Debug options**

This is the easiest way to configure the plugin - no file editing required!

### 2. JSON Configuration File (Advanced)

For advanced settings or system-wide defaults, you can use a JSON configuration file (`meta-config.json`). This allows you to:

- Update API endpoints without recompiling
- Set defaults that apply to all accounts
- Configure settings not exposed in the UI

**Priority:** Account settings (UI) take precedence over JSON config values.

The plugin will work with default values if no configuration is provided.

---

## Configuration File Locations

The plugin searches for configuration files in this order:

| Priority | Location | Description |
|----------|----------|-------------|
| 1 | `~/.purple/meta-config.json` | User-specific override (Linux/macOS) |
| 1 | `%APPDATA%\.purple\meta-config.json` | User-specific override (Windows) |
| 2 | `/etc/purple/meta-config.json` | System-wide configuration (Linux) |
| 3 | Built-in defaults | Compiled into the plugin |

### Creating Your Configuration File

1. Copy the sample configuration from the plugin's `config/` directory:

   **Linux/macOS:**
   ```bash
   cp /usr/share/purple/meta/meta-config.json ~/.purple/meta-config.json
   ```

   **Windows:**
   ```cmd
   copy "C:\Program Files\Pidgin\share\purple\meta\meta-config.json" "%APPDATA%\.purple\meta-config.json"
   ```

2. Edit the file with your preferred text editor.

3. Restart Pidgin/Finch for changes to take effect.

---

## Basic Setup

### Minimal Configuration for Instagram

```json
{
  "version": 1,
  "features": {
    "instagram_enabled": true,
    "messenger_enabled": false
  },
  "instagram": {
    "app_version": "275.0.0.27.98",
    "version_code": "458229237"
  }
}
```

### Minimal Configuration for Messenger

```json
{
  "version": 1,
  "features": {
    "messenger_enabled": true,
    "instagram_enabled": false
  },
  "messenger": {
    "oauth_client_id": "YOUR_META_APP_ID"
  }
}
```

---

## Configuration Reference

### Root Level Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | integer | `1` | Configuration file version |
| `last_updated` | integer | `0` | Unix timestamp of last update |
| `update_url` | string | GitHub raw URL | URL to check for config updates |
| `debug_mode` | boolean | `false` | Enable verbose debug logging |
| `log_api_calls` | boolean | `false` | Log all API requests (sensitive!) |
| `log_websocket` | boolean | `false` | Log WebSocket traffic (sensitive!) |

### Messenger Configuration (`messenger` section)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `oauth_auth_url` | string | FB OAuth URL | OAuth authorization endpoint |
| `oauth_token_url` | string | FB token URL | OAuth token exchange endpoint |
| `graph_api_base` | string | Graph API URL | Facebook Graph API base URL |
| `mqtt_endpoint` | string | FB MQTT URL | WebSocket/MQTT endpoint |
| `mqtt_origin` | string | facebook.com | Origin header for WebSocket |
| `graph_api_version` | string | `"v18.0"` | Graph API version to use |
| `oauth_client_id` | string | (required) | Your Meta App ID |
| `oauth_redirect_uri` | string | localhost | OAuth callback URL |
| `oauth_scope` | string | messaging scopes | OAuth permissions to request |
| `rate_limit_calls` | integer | `200` | Max API calls per window |
| `rate_limit_window` | integer | `3600` | Rate limit window (seconds) |
| `min_request_interval_ms` | integer | `100` | Min time between requests (ms) |

### Instagram Configuration (`instagram` section)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_base` | string | i.instagram.com | Instagram API base URL |
| `graphql_api` | string | instagram.com/api | GraphQL API endpoint |
| `realtime_url` | string | IG WebSocket URL | Realtime messaging endpoint |
| `upload_url` | string | rupload URL | Media upload endpoint |
| `app_version` | string | `"275.0.0.27.98"` | Instagram app version to simulate |
| `version_code` | string | `"458229237"` | Instagram version code |
| `sig_key_version` | string | `"4"` | Signature key version |
| `user_agent` | string | (auto-generated) | HTTP User-Agent header |
| `device_manufacturer` | string | `"samsung"` | Simulated device manufacturer |
| `device_model` | string | `"SM-G975F"` | Simulated device model |
| `android_version` | string | `"30"` | Simulated Android API level |
| `android_release` | string | `"11"` | Simulated Android version |
| `rate_limit_calls` | integer | `100` | Max API calls per window |
| `rate_limit_window` | integer | `3600` | Rate limit window (seconds) |
| `min_request_interval_ms` | integer | `200` | Min time between requests (ms) |
| `x_ig_capabilities` | string | `"3brTvwE="` | X-IG-Capabilities header |
| `x_ig_connection_type` | string | `"WIFI"` | X-IG-Connection-Type header |
| `x_ig_app_id` | string | `"567067343352427"` | X-IG-App-ID header |

### WebSocket Configuration (`websocket` section)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `connect_timeout` | integer | `30` | Connection timeout (seconds) |
| `ping_interval` | integer | `30` | Keepalive ping interval (seconds) |
| `pong_timeout` | integer | `10` | Pong response timeout (seconds) |
| `reconnect_delay` | integer | `5` | Initial reconnect delay (seconds) |
| `max_reconnect_delay` | integer | `300` | Maximum reconnect delay (seconds) |
| `max_reconnect_attempts` | integer | `10` | Max reconnection attempts |
| `topic_messages` | string | `"/t_ms"` | Messages topic |
| `topic_typing` | string | `"/typing"` | Typing indicator topic |
| `topic_presence` | string | `"/presence"` | Presence updates topic |

### Security Configuration (`security` section)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `warn_plaintext_storage` | boolean | `true` | Warn about plaintext token storage |
| `obfuscate_tokens` | boolean | `true` | Apply basic token obfuscation |
| `max_token_age` | integer | `86400` | Force re-auth after (seconds) |
| `max_failed_logins` | integer | `5` | Failed logins before lockout |
| `login_lockout_duration` | integer | `3600` | Lockout duration (seconds) |
| `require_tls_1_2` | boolean | `true` | Require TLS 1.2 or higher |
| `verify_certificates` | boolean | `true` | Verify SSL certificates |
| `initial_backoff` | integer | `1` | Initial rate limit backoff (seconds) |
| `max_backoff` | integer | `600` | Maximum backoff (seconds) |
| `backoff_multiplier` | integer | `2` | Exponential backoff multiplier |

### Feature Flags (`features` section)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `messenger_enabled` | boolean | `true` | Enable Messenger service |
| `instagram_enabled` | boolean | `true` | Enable Instagram service |
| `presence_enabled` | boolean | `true` | Show online/offline status |
| `typing_enabled` | boolean | `true` | Send/receive typing indicators |
| `read_receipts_enabled` | boolean | `true` | Send/receive read receipts |
| `reactions_enabled` | boolean | `true` | Enable message reactions |
| `attachments_enabled` | boolean | `true` | Enable media attachments |
| `group_chats_enabled` | boolean | `true` | Enable group conversations |
| `ig_pending_inbox_enabled` | boolean | `true` | Show pending message requests |
| `ig_disappearing_enabled` | boolean | `true` | Support disappearing messages |
| `ig_voice_enabled` | boolean | `true` | Enable voice messages |

---

## Instagram Setup

### Step 1: Create an Account in Pidgin

1. Open Pidgin and go to **Accounts → Manage Accounts**
2. Click **Add...**
3. Select **Meta (Messenger + Instagram)** as the protocol
4. Enter your Instagram username
5. In the **Advanced** tab, set **Service Mode** to `instagram`
6. Click **Add**

### Step 2: Configure the Plugin

Create or edit `~/.purple/meta-config.json`:

```json
{
  "version": 1,
  "features": {
    "instagram_enabled": true
  },
  "instagram": {
    "app_version": "275.0.0.27.98",
    "version_code": "458229237",
    "rate_limit_calls": 60,
    "rate_limit_window": 3600,
    "min_request_interval_ms": 500
  },
  "security": {
    "warn_plaintext_storage": true
  }
}
```

### Step 3: Authentication

When you enable the account, you'll be prompted to authenticate. Instagram may require:

- **2FA Code**: Enter the code from your authenticator app or SMS
- **Email/Phone Verification**: Check your email or phone for a verification code
- **Checkpoint Challenge**: Complete a security challenge in your browser

### Important Instagram Notes

⚠️ **Warning**: Instagram's private API is not officially supported. Using this plugin may:

- Trigger security challenges
- Result in temporary account restrictions
- Violate Instagram's Terms of Service

**Recommendations:**

1. Use a secondary/test account initially
2. Keep rate limits conservative (lower `rate_limit_calls`)
3. Increase `min_request_interval_ms` to 500-1000ms
4. Don't spam messages or actions
5. If you get blocked, wait 24-48 hours before retrying

### Updating Instagram App Version

Instagram frequently updates their app. When the simulated version becomes outdated, you may experience issues. To update:

1. Find the current Instagram APK version (check APKMirror or similar)
2. Update these fields in your config:

```json
{
  "instagram": {
    "app_version": "NEW_VERSION_HERE",
    "version_code": "NEW_VERSION_CODE_HERE"
  }
}
```

---

## Messenger Setup

### Step 1: Create a Meta Developer App

1. Go to [developers.facebook.com](https://developers.facebook.com/)
2. Click **My Apps → Create App**
3. Choose **Business** type
4. Fill in app details and create
5. Add the **Messenger** product to your app
6. Note your **App ID** and **App Secret**

### Step 2: Configure OAuth

In your Meta app settings:

1. Go to **Settings → Basic**
2. Add `https://localhost/oauth/callback` to **Valid OAuth Redirect URIs**
3. Save changes

### Step 3: Update Plugin Configuration

Edit `~/.purple/meta-config.json`:

```json
{
  "version": 1,
  "features": {
    "messenger_enabled": true
  },
  "messenger": {
    "oauth_client_id": "YOUR_APP_ID_HERE",
    "oauth_redirect_uri": "https://localhost/oauth/callback",
    "oauth_scope": "pages_messaging,pages_read_engagement"
  }
}
```

### Step 4: Create Account in Pidgin

1. Open Pidgin and go to **Accounts → Manage Accounts**
2. Click **Add...**
3. Select **Meta (Messenger + Instagram)** as the protocol
4. Enter any identifier (your FB name/email)
5. In the **Advanced** tab, set **Service Mode** to `messenger`
6. Click **Add**

When you connect, a browser window will open for OAuth authentication.

---

## Security Considerations

### ⚠️ Token Storage Warning

**libpurple stores account data in PLAINTEXT files!**

- **Linux/macOS**: `~/.purple/accounts.xml`
- **Windows**: `%APPDATA%\.purple\accounts.xml`

Your access tokens are stored in these files with only basic obfuscation (NOT encryption). Anyone with access to these files can read your credentials.

**Recommendations:**

1. Use full-disk encryption on your computer
2. Set restrictive file permissions:
   ```bash
   chmod 600 ~/.purple/accounts.xml
   chmod 700 ~/.purple/
   ```
3. Consider the `warn_plaintext_storage` setting (enabled by default)

### Rate Limiting

Both Instagram and Messenger have rate limits. Exceeding them can result in:

- Temporary API blocks
- Account restrictions
- Permanent bans (repeated violations)

**Conservative settings for Instagram:**

```json
{
  "instagram": {
    "rate_limit_calls": 50,
    "rate_limit_window": 3600,
    "min_request_interval_ms": 1000
  }
}
```

### TLS Security

The plugin requires TLS 1.2+ by default. Don't disable this unless absolutely necessary:

```json
{
  "security": {
    "require_tls_1_2": true,
    "verify_certificates": true
  }
}
```

---

## Troubleshooting

### Common Issues

#### "Instagram is disabled in configuration"

Ensure `features.instagram_enabled` is `true` in your config file.

#### "Connection timed out"

1. Check your internet connection
2. Try increasing `websocket.connect_timeout`
3. Verify endpoints are correct and accessible

#### "Rate limited" messages

1. Reduce `rate_limit_calls`
2. Increase `min_request_interval_ms`
3. Wait before retrying (check backoff settings)

#### "Invalid token format"

Your stored token may be corrupted. Try:

1. Go to **Accounts → Manage Accounts**
2. Select the Meta account and click **Modify**
3. Clear saved credentials
4. Reconnect and re-authenticate

#### "Checkpoint required"

Instagram detected unusual activity. You need to:

1. Open Instagram in a browser
2. Complete any security challenges
3. Wait a few hours before reconnecting

#### Configuration not loading

1. Verify JSON syntax (use a JSON validator)
2. Check file permissions
3. Look for errors in Pidgin's debug log

### Enabling Debug Mode

For troubleshooting, enable debug logging:

```json
{
  "debug_mode": true,
  "log_api_calls": true,
  "log_websocket": true
}
```

Then view logs:

- **Pidgin**: Help → Debug Window
- **Finch**: Run with `-d` flag

⚠️ **Warning**: Debug logs may contain sensitive information. Disable these options after troubleshooting.

---

## Advanced Configuration

### Complete Example Configuration

```json
{
  "version": 1,
  "last_updated": 1704067200,
  "update_url": "https://raw.githubusercontent.com/libpurple-meta/libpurple-meta/main/config/meta-config.json",

  "messenger": {
    "oauth_auth_url": "https://www.facebook.com/v18.0/dialog/oauth",
    "oauth_token_url": "https://graph.facebook.com/v18.0/oauth/access_token",
    "graph_api_base": "https://graph.facebook.com/v18.0",
    "mqtt_endpoint": "wss://edge-chat.facebook.com/chat",
    "mqtt_origin": "https://www.facebook.com",
    "graph_api_version": "v18.0",
    "oauth_client_id": "YOUR_APP_ID",
    "oauth_redirect_uri": "https://localhost/oauth/callback",
    "oauth_scope": "pages_messaging,pages_read_engagement",
    "rate_limit_calls": 200,
    "rate_limit_window": 3600,
    "min_request_interval_ms": 100
  },

  "instagram": {
    "api_base": "https://i.instagram.com/api/v1",
    "graphql_api": "https://www.instagram.com/api/graphql",
    "realtime_url": "wss://edge-chat.instagram.com/chat",
    "upload_url": "https://i.instagram.com/rupload_igphoto/",
    "app_version": "275.0.0.27.98",
    "version_code": "458229237",
    "sig_key_version": "4",
    "user_agent": "Instagram 275.0.0.27.98 Android (30/11; 420dpi; 1080x2220; samsung; SM-G975F; beyond2; exynos9820; en_US; 458229237)",
    "device_manufacturer": "samsung",
    "device_model": "SM-G975F",
    "android_version": "30",
    "android_release": "11",
    "rate_limit_calls": 60,
    "rate_limit_window": 3600,
    "min_request_interval_ms": 500,
    "x_ig_capabilities": "3brTvwE=",
    "x_ig_connection_type": "WIFI",
    "x_ig_app_id": "567067343352427"
  },

  "websocket": {
    "connect_timeout": 30,
    "ping_interval": 30,
    "pong_timeout": 10,
    "reconnect_delay": 5,
    "max_reconnect_delay": 300,
    "max_reconnect_attempts": 10,
    "topic_messages": "/t_ms",
    "topic_message_sync": "/messaging_events",
    "topic_typing": "/typing",
    "topic_presence": "/presence",
    "topic_read_receipts": "/t_rt",
    "topic_thread_updates": "/thread_updates",
    "ig_topic_direct": "/ig_direct",
    "ig_topic_message_sync": "/ig_message_sync",
    "ig_topic_realtime": "/ig_realtime_sub"
  },

  "security": {
    "warn_plaintext_storage": true,
    "obfuscate_tokens": true,
    "max_token_age": 86400,
    "max_failed_logins": 5,
    "login_lockout_duration": 3600,
    "require_tls_1_2": true,
    "verify_certificates": true,
    "initial_backoff": 1,
    "max_backoff": 600,
    "backoff_multiplier": 2
  },

  "features": {
    "messenger_enabled": true,
    "instagram_enabled": true,
    "presence_enabled": true,
    "typing_enabled": true,
    "read_receipts_enabled": true,
    "reactions_enabled": true,
    "attachments_enabled": true,
    "group_chats_enabled": true,
    "ig_pending_inbox_enabled": true,
    "ig_disappearing_enabled": true,
    "ig_voice_enabled": true
  },

  "debug_mode": false,
  "log_api_calls": false,
  "log_websocket": false
}
```

### Environment-Specific Configurations

You can maintain different configurations for testing:

```bash
# Use test config
cp ~/.purple/meta-config.json ~/.purple/meta-config.json.prod
cp ~/.purple/meta-config-test.json ~/.purple/meta-config.json

# Restore production config
cp ~/.purple/meta-config.json.prod ~/.purple/meta-config.json
```

### Automatic Configuration Updates

The plugin can check for configuration updates. Set the `update_url` to a trusted source:

```json
{
  "update_url": "https://your-server.com/meta-config.json"
}
```

The plugin will notify you when updates are available (it won't auto-update).

---

## Getting Help

- **GitHub Issues**: Report bugs and request features
- **Debug Logs**: Always include relevant logs when reporting issues
- **Configuration**: Share your config (remove sensitive data like App IDs)

---

*Last updated: 2025*