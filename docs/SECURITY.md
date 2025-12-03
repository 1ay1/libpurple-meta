# libpurple-meta Security Guide

This document covers security considerations, best practices, and known risks when using the libpurple-meta plugin.

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Token Storage Security](#token-storage-security)
3. [Network Security](#network-security)
4. [Rate Limiting & Anti-Bot Protection](#rate-limiting--anti-bot-protection)
5. [Two-Factor Authentication](#two-factor-authentication)
6. [Privacy Considerations](#privacy-considerations)
7. [Risk Assessment](#risk-assessment)
8. [Security Configuration](#security-configuration)
9. [Incident Response](#incident-response)

---

## Security Overview

### What This Plugin Does

libpurple-meta connects to Meta's messaging services (Facebook Messenger and Instagram DMs) using:

- **Messenger**: Official Graph API with OAuth 2.0 authentication
- **Instagram**: Unofficial private API (reverse-engineered)

### Key Security Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Plaintext token storage | **High** | Disk encryption, file permissions |
| Instagram ToS violation | **Medium** | Use at your own risk |
| Rate limit bans | **Medium** | Conservative rate settings |
| Session hijacking | **Medium** | Secure your computer |
| Man-in-the-middle | **Low** | TLS 1.2+ enforced |

---

## Token Storage Security

### ⚠️ Critical Warning

**libpurple stores all account data in PLAINTEXT files!**

This is a fundamental limitation of libpurple, not this plugin. Your access tokens, session cookies, and credentials are stored in easily readable files.

### File Locations

| OS | Location |
|----|----------|
| Linux | `~/.purple/accounts.xml` |
| macOS | `~/.purple/accounts.xml` |
| Windows | `%APPDATA%\.purple\accounts.xml` |

### What's Stored

- OAuth access tokens
- Session cookies
- Device identifiers
- User IDs

### Mitigation Strategies

#### 1. Full Disk Encryption (Recommended)

Enable full disk encryption on your system:

- **Windows**: BitLocker
- **macOS**: FileVault
- **Linux**: LUKS/dm-crypt

#### 2. File Permissions (Linux/macOS)

Restrict access to the Purple directory:

```bash
# Set restrictive permissions
chmod 700 ~/.purple
chmod 600 ~/.purple/accounts.xml
chmod 600 ~/.purple/meta-config.json

# Verify permissions
ls -la ~/.purple/
```

#### 3. Encrypted Home Directory

On Linux, consider an encrypted home directory:

```bash
# Check if home is encrypted
mount | grep /home
```

#### 4. Password Manager Integration

For maximum security, store credentials externally and enter them each session (not currently supported, but planned).

### Token Obfuscation

The plugin applies basic XOR obfuscation to stored tokens:

```json
{
  "security": {
    "obfuscate_tokens": true
  }
}
```

**Important**: This is NOT encryption! It only prevents casual viewing. A determined attacker can easily reverse the obfuscation.

### Security Warning Dialog

The plugin shows a one-time warning about plaintext storage. To re-enable:

```json
{
  "security": {
    "warn_plaintext_storage": true
  }
}
```

---

## Network Security

### TLS Requirements

The plugin enforces TLS 1.2+ for all connections:

```json
{
  "security": {
    "require_tls_1_2": true,
    "verify_certificates": true
  }
}
```

**Never disable these settings** unless absolutely necessary for debugging.

### Certificate Validation

All SSL/TLS certificates are validated against system trust stores. The plugin will reject:

- Self-signed certificates
- Expired certificates
- Certificates with wrong hostnames
- Revoked certificates

### WebSocket Security

MQTT/WebSocket connections use:

- WSS (WebSocket Secure) protocol
- TLS 1.2+ encryption
- Certificate pinning (where supported)

### Proxy Considerations

If using a proxy:

1. Ensure the proxy supports TLS passthrough
2. Don't use HTTP proxies for authentication traffic
3. Be aware that proxy operators can see metadata (not content)

---

## Rate Limiting & Anti-Bot Protection

### Why Rate Limits Matter

Meta aggressively detects and blocks automated access. Violations can result in:

- Temporary API blocks (hours to days)
- Account restrictions
- Permanent account suspension
- IP-level blocks

### Instagram Protection

Instagram's anti-bot measures include:

| Detection Method | How to Avoid |
|------------------|--------------|
| Request frequency | Keep intervals ≥500ms |
| Request patterns | Don't perform rapid repeated actions |
| Device fingerprinting | Use consistent device simulation |
| IP reputation | Avoid VPNs/datacenter IPs |
| Behavioral analysis | Act like a human |

### Recommended Rate Limits

**Conservative (Safest):**
```json
{
  "instagram": {
    "rate_limit_calls": 30,
    "rate_limit_window": 3600,
    "min_request_interval_ms": 2000
  }
}
```

**Moderate:**
```json
{
  "instagram": {
    "rate_limit_calls": 60,
    "rate_limit_window": 3600,
    "min_request_interval_ms": 500
  }
}
```

**Aggressive (Not Recommended):**
```json
{
  "instagram": {
    "rate_limit_calls": 100,
    "rate_limit_window": 3600,
    "min_request_interval_ms": 200
  }
}
```

### Exponential Backoff

When rate limited (HTTP 429), the plugin uses exponential backoff:

```json
{
  "security": {
    "initial_backoff": 1,
    "max_backoff": 600,
    "backoff_multiplier": 2
  }
}
```

This means: 1s → 2s → 4s → 8s → ... → 600s max

### Signs You're Being Rate Limited

- Repeated connection failures
- "Please wait a few minutes" errors
- HTTP 429 responses in debug logs
- Checkpoint challenges appearing frequently

---

## Two-Factor Authentication

### Supported 2FA Methods

| Method | Instagram | Messenger |
|--------|-----------|-----------|
| SMS Code | ✅ | ✅ |
| TOTP (Authenticator App) | ✅ | ✅ |
| Email Code | ✅ | ✅ |
| Security Keys | ❌ | ❌ |

### 2FA Workflow

1. Plugin detects 2FA requirement
2. Dialog prompts for code
3. You enter the code
4. Plugin submits for verification
5. On success, session continues

### Handling 2FA Issues

If 2FA verification fails:

1. Wait for the code to refresh
2. Ensure you're entering the current code
3. Check for SMS delays
4. Try logging into the official app first

### Security Keys

Hardware security keys (FIDO2/WebAuthn) are **not currently supported**. If you have security keys enabled:

1. Use a backup method (SMS/TOTP)
2. Or temporarily disable security keys for initial auth

---

## Privacy Considerations

### What Data the Plugin Accesses

| Data Type | Access Level |
|-----------|--------------|
| Messages | Read/Write |
| Contacts | Read |
| Presence/Online Status | Read |
| Typing Indicators | Read/Write |
| Profile Information | Read |
| Media (Photos/Videos) | Read/Write |

### Local Data Storage

The plugin stores locally:

- Message cache (in memory, not persisted)
- Authentication tokens (in accounts.xml)
- Device identifiers (in accounts.xml)
- Configuration (in meta-config.json)

### Logging

By default, the plugin:

- ✅ Logs connection status
- ✅ Logs errors
- ❌ Does NOT log message content
- ❌ Does NOT log tokens (redacted)

Debug mode changes this:

```json
{
  "debug_mode": true,
  "log_api_calls": true
}
```

**Warning**: Debug logs may contain sensitive data. Disable after troubleshooting.

### Data Sent to Meta

All messaging data goes through Meta's servers. Meta can see:

- Message content
- Sender/recipient information
- Timestamps
- Device information
- IP addresses

This is true for the official apps too—it's inherent to the service.

---

## Risk Assessment

### Instagram Private API Risks

| Risk | Likelihood | Impact | Notes |
|------|------------|--------|-------|
| Account suspension | Low-Medium | High | More likely with aggressive use |
| Temporary block | Medium | Medium | Usually 24-48 hours |
| ToS violation | Certain | Variable | Using private API violates ToS |
| API breakage | Medium | Medium | Updates may break functionality |

### Messenger Graph API Risks

| Risk | Likelihood | Impact | Notes |
|------|------------|--------|-------|
| API deprecation | Low | Medium | Graph API is stable |
| Rate limiting | Low | Low | Generous limits |
| Token expiration | Medium | Low | Plugin handles refresh |
| Scope changes | Low | Medium | Meta may change permissions |

### General Risks

| Risk | Likelihood | Impact | Notes |
|------|------------|--------|-------|
| Token theft | Low | High | Mitigate with disk encryption |
| MITM attack | Very Low | High | TLS prevents this |
| Plugin vulnerabilities | Low | Medium | Keep plugin updated |

---

## Security Configuration

### Maximum Security Configuration

```json
{
  "security": {
    "warn_plaintext_storage": true,
    "obfuscate_tokens": true,
    "max_token_age": 43200,
    "max_failed_logins": 3,
    "login_lockout_duration": 7200,
    "require_tls_1_2": true,
    "verify_certificates": true,
    "initial_backoff": 5,
    "max_backoff": 900,
    "backoff_multiplier": 3
  },
  "instagram": {
    "rate_limit_calls": 30,
    "min_request_interval_ms": 2000
  },
  "features": {
    "presence_enabled": false,
    "typing_enabled": false
  },
  "debug_mode": false,
  "log_api_calls": false,
  "log_websocket": false
}
```

### Security-Related Settings Explained

| Setting | Security Benefit |
|---------|------------------|
| `max_token_age: 43200` | Force re-auth every 12 hours |
| `max_failed_logins: 3` | Lock out after 3 failures |
| `login_lockout_duration: 7200` | 2-hour lockout |
| `presence_enabled: false` | Don't broadcast online status |
| `typing_enabled: false` | Don't send typing indicators |
| `min_request_interval_ms: 2000` | Slower = less detection |

---

## Incident Response

### If You Suspect Token Theft

1. **Immediately**: Disconnect the account in Pidgin
2. **Change passwords** on Facebook/Instagram via official website
3. **Revoke sessions** in Facebook/Instagram settings
4. **Delete** `~/.purple/accounts.xml`
5. **Review** account activity for unauthorized access
6. **Re-enable 2FA** if disabled

### If Your Account Gets Blocked

1. **Don't panic** - most blocks are temporary
2. **Wait 24-48 hours** before retrying
3. **Log into official app** to clear any challenges
4. **Reduce rate limits** in configuration
5. **Use a fresh device ID**:
   - Delete the account in Pidgin
   - Remove stored settings
   - Re-add the account

### If You Detect Suspicious Activity

1. Check Pidgin's debug log for anomalies
2. Review `~/.purple/` for unexpected files
3. Scan your system for malware
4. Change passwords
5. Report issues on GitHub (remove sensitive data)

### Reporting Security Vulnerabilities

If you find a security vulnerability in this plugin:

1. **Do NOT** open a public GitHub issue
2. Email the maintainers directly
3. Allow 90 days for a fix before disclosure
4. Include:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

---

## Security Checklist

Before using this plugin:

- [ ] Full disk encryption enabled
- [ ] Strong system password set
- [ ] 2FA enabled on Meta accounts
- [ ] File permissions restricted on ~/.purple/
- [ ] Rate limits configured conservatively
- [ ] Understood the ToS violation risk (Instagram)
- [ ] Debug logging disabled
- [ ] Backup authentication method available

---

## Further Reading

- [libpurple Security Documentation](https://developer.pidgin.im/wiki/Security)
- [Meta Graph API Security Best Practices](https://developers.facebook.com/docs/graph-api/security)
- [OWASP Authentication Guidelines](https://owasp.org/www-project-web-security-testing-guide/)

---

*Last updated: 2025*