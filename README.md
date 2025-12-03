# libpurple-meta

A libpurple protocol plugin for **Facebook Messenger** and **Instagram Direct Messages**.

This plugin enables Pidgin (and other libpurple-based clients) to connect to Meta's messaging platforms using the modern Graph API and WebSocket connections.

## 📚 Documentation

- **[Quick Start Guide](docs/QUICKSTART.md)** - Get up and running in 5 minutes
- **[Configuration Guide](docs/CONFIGURATION.md)** - Complete configuration reference
- **[Security Guide](docs/SECURITY.md)** - Security best practices and risk assessment

## ⚠️ Disclaimer

This is an **unofficial** third-party plugin. It is not affiliated with, endorsed by, or connected to Meta Platforms, Inc. Use at your own risk. Meta's Terms of Service may prohibit the use of unofficial clients.

## Features

### Facebook Messenger
- ✅ Send and receive text messages
- ✅ Typing indicators
- ✅ Read receipts
- ✅ Presence/online status
- ✅ Group chats
- ✅ Message reactions
- ✅ Image/file attachments
- ✅ OAuth authentication

### Instagram DMs
- ✅ Send and receive text messages
- ✅ Typing indicators ("seen" status)
- ✅ Message reactions (❤️ and emoji)
- ✅ Group threads
- ✅ Message requests (pending inbox)
- ✅ Link sharing
- ⚠️ Limited presence support (Instagram doesn't expose this)
- ⚠️ Media uploads (partial implementation)

## Requirements

### Build Dependencies

- GLib 2.52+
- GObject 2.52+
- GIO 2.52+
- json-glib 1.4+
- zlib
- **libpurple 3.0+** (libpurple 2.x is not supported due to API differences)
- Meson 0.56+
- Ninja (or another Meson backend)

> **Note**: This plugin requires libpurple 3.x (Pidgin 3). The libpurple 2.x API used by Pidgin 2 has significant differences in HTTP handling, message structures, and connection management that would require substantial rewrites to support.

### Optional Dependencies

- libsoup 2.4 or 3.0 (alternative WebSocket implementation)

### Installing Dependencies

**Debian/Ubuntu:**
```bash
sudo apt install build-essential meson ninja-build \
    libglib2.0-dev libjson-glib-dev zlib1g-dev \
    libpurple-dev
```

**Fedora:**
```bash
sudo dnf install meson ninja-build \
    glib2-devel json-glib-devel zlib-devel \
    libpurple-devel
```

**Arch Linux:**
```bash
sudo pacman -S meson ninja glib2 json-glib zlib libpurple
```

**macOS (Homebrew):**
```bash
brew install meson ninja glib json-glib zlib pidgin
```

**Windows (MSYS2):**
```bash
pacman -S mingw-w64-x86_64-meson mingw-w64-x86_64-ninja \
    mingw-w64-x86_64-glib2 mingw-w64-x86_64-json-glib \
    mingw-w64-x86_64-zlib mingw-w64-x86_64-libpurple
```

## Building

```bash
# Clone the repository
git clone https://github.com/libpurple-meta/libpurple-meta.git
cd libpurple-meta

# Configure the build
meson setup build

# Build
meson compile -C build

# Install (may require sudo)
meson install -C build
```

### Build Options

```bash
# Enable debug build
meson setup build -Ddebug=true

# Specify custom install prefix
meson setup build --prefix=/usr/local

# Build for libpurple 3.x specifically
meson setup build -Dpurple_version=3
```

## Installation

After building, the plugin (`prpl-meta.so` on Linux, `prpl-meta.dll` on Windows) will be installed to your libpurple plugins directory.

**Manual installation:**
- Linux: `~/.purple/plugins/` or `/usr/lib/purple-2/plugins/`
- macOS: `~/Library/Application Support/Purple/plugins/`
- Windows: `%APPDATA%\.purple\plugins\`

## Configuration

The plugin uses an external JSON configuration file (`meta-config.json`) that allows you to update endpoints, rate limits, and feature flags without recompiling.

**Configuration file locations:**
- Linux/macOS: `~/.purple/meta-config.json`
- Windows: `%APPDATA%\.purple\meta-config.json`

For complete configuration options, see the **[Configuration Guide](docs/CONFIGURATION.md)**.

### Quick Start

1. Copy the sample config to your Purple directory:
   ```bash
   cp config/meta-config.json ~/.purple/meta-config.json
   ```

2. Edit the configuration for your needs (Instagram or Messenger)

3. Add an account in Pidgin with the "Meta (Messenger + Instagram)" protocol

### Setting Up a Meta Developer App (Messenger)

For Messenger OAuth authentication:

1. Go to [Meta for Developers](https://developers.facebook.com/)
2. Create a new app (Business type)
3. Add the "Messenger" product
4. Configure OAuth redirect URIs: `https://localhost/oauth/callback`
5. Copy your App ID to your `meta-config.json`

### Adding an Account in Pidgin

1. Open Pidgin → Accounts → Manage Accounts → Add
2. Select "Meta (Messenger + Instagram)" as the protocol
3. Enter your username
4. In the **Advanced** tab, set **Service Mode**:
   - `messenger` - For Facebook Messenger only
   - `instagram` - For Instagram DMs only
   - `unified` - For both services
5. Click "Add" to initiate the login flow
6. Complete authentication when prompted

## Architecture

```
libpurple-meta/
├── src/
│   ├── prpl-meta.c          # Main plugin entry point
│   ├── prpl-meta.h          # Shared types and structures
│   ├── common/
│   │   ├── meta-auth.c/.h       # OAuth authentication
│   │   ├── meta-websocket.c/.h  # WebSocket/MQTT connection
│   │   ├── meta-config.c/.h     # External configuration system
│   │   └── meta-security.c/.h   # Security, validation, rate limiting
│   ├── messenger/
│   │   └── messenger.c/.h   # Messenger-specific implementation
│   └── instagram/
│       └── instagram.c/.h   # Instagram-specific implementation
├── config/
│   └── meta-config.json     # Sample configuration file
├── docs/
│   ├── QUICKSTART.md        # Quick start guide
│   ├── CONFIGURATION.md     # Full configuration reference
│   └── SECURITY.md          # Security best practices
├── meson.build              # Build configuration
└── README.md
```

### Key Components

- **Transport Abstraction Layer**: Unified `MetaService` interface for switching between Messenger and Instagram
- **WebSocket/MQTT Handler**: Manages persistent connections to Meta's real-time messaging endpoints
- **OAuth Module**: Handles browser-based authentication with PKCE support
- **Cookie Authentication**: Alternative auth method using browser session cookies

## How It Works

### Messenger Protocol (2025)

Facebook Messenger no longer supports XMPP. This plugin uses:

1. **OAuth 2.0** for authentication (browser-based flow)
2. **Graph API v18.0** for fetching threads, messages, and user data
3. **WebSocket + MQTT-like protocol** for real-time message delivery
4. Topic subscriptions: `/t_ms`, `/messaging_events`, `/typing`, `/presence`

### Instagram DM Protocol

Instagram doesn't provide an official DM API. This plugin reverse-engineers:

1. **Private API** (`i.instagram.com/api/v1`)
2. **GraphQL endpoints** for some operations
3. **Cookie/session-based authentication**

## Troubleshooting

### "Authentication failed"
- Ensure your Meta account doesn't have 2FA issues
- Try clearing credentials: Account → Re-authenticate
- Check if your IP is rate-limited by Meta

### "Connection dropped repeatedly"
- Meta may be detecting unofficial client usage
- Reduce rate limits in your configuration
- Wait a few hours before reconnecting

### "Messages not sending"
- Check your internet connection
- Verify the WebSocket connection is established (enable debug logging)
- Rate limiting may be in effect

### "Instagram is disabled in configuration"
- Ensure `features.instagram_enabled` is `true` in `meta-config.json`

### Enable Debug Logging

In your `meta-config.json`:
```json
{
  "debug_mode": true,
  "log_api_calls": true
}
```

In Pidgin: Help → Debug Window

Or set environment variable:
```bash
PURPLE_DEBUG=1 pidgin
```

For more troubleshooting tips, see the **[Configuration Guide](docs/CONFIGURATION.md#troubleshooting)**.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Notes

- Follow the existing code style
- Use `meta_debug()`, `meta_warning()`, `meta_error()` for logging
- Test with both Messenger and Instagram
- Be mindful of rate limits during testing

## Related Projects

- [purple-facebook](https://github.com/dequis/purple-facebook) - Older Messenger plugin (abandoned)
- [bitlbee-facebook](https://github.com/bitlbee/bitlbee-facebook) - Facebook plugin for BitlBee
- [mautrix-facebook](https://github.com/mautrix/facebook) - Matrix-Facebook bridge
- [instagram-private-api](https://github.com/dilame/instagram-private-api) - Node.js Instagram API

## Security

**Important**: libpurple stores account credentials in plaintext files. Please read the **[Security Guide](docs/SECURITY.md)** before using this plugin.

Key security considerations:
- Use full-disk encryption on your computer
- Restrict file permissions on `~/.purple/`
- Keep rate limits conservative to avoid bans
- Be aware that using Instagram's private API violates their ToS

## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0).

See [LICENSE](LICENSE) for the full text.

## Acknowledgments

- The Pidgin/libpurple team for the excellent IM framework
- Contributors to reverse-engineering efforts of Meta's protocols
- The open-source community for various reference implementations

---

**Note:** This plugin is for educational and personal use. Commercial use or large-scale deployment may violate Meta's Terms of Service.