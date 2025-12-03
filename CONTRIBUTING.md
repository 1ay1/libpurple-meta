# Contributing to libpurple-meta

Thanks for your interest in contributing! This doc covers how to get involved.

## Getting Started

1. Fork the repo on GitHub
2. Clone your fork locally
3. Set up the build environment (see README.md)
4. Create a branch for your changes

## Building for Development

```bash
meson setup build -Dbuildtype=debug
meson compile -C build
```

Debug builds have extra logging and no optimization, which makes debugging easier.

## Code Style

We try to keep things consistent:

- C11 standard
- 4-space indentation (no tabs)
- Opening braces on the same line as the statement
- Function names: `module_verb_noun()` (e.g., `instagram_send_message()`)
- Use `g_` prefixed GLib functions for memory, strings, etc.
- Comments for anything non-obvious

Example:

```c
gboolean instagram_send_message(MetaAccount *account, const char *to,
                                 const char *message)
{
    if (!account || !to || !message) {
        return FALSE;
    }
    
    /* Validate input before sending */
    if (!meta_security_validate_thread_id(to)) {
        meta_warning("Invalid thread ID");
        return FALSE;
    }
    
    // ... rest of implementation
}
```

## Logging

Use the provided macros:

- `meta_debug()` - verbose info, only shown with debug enabled
- `meta_warning()` - something's wrong but we can continue
- `meta_error()` - something's broken

Don't log sensitive data (tokens, message content, etc.). Use `meta_security_sanitize_for_log()` if you need to log user-provided input.

## Testing

We don't have a great test suite yet (contributions welcome!). At minimum:

1. Make sure it compiles without warnings
2. Test with both Messenger and Instagram if your change touches shared code
3. Test the specific feature you changed

To test without installing system-wide:

```bash
# Point libpurple at your build directory
export PURPLE_PLUGIN_PATH=$PWD/build
pidgin -d
```

## Submitting Changes

1. Make sure your code compiles cleanly
2. Test your changes
3. Commit with a clear message explaining what and why
4. Push to your fork
5. Open a pull request

### Commit Messages

Try to write useful commit messages:

```
instagram: fix rate limiting when inbox sync fails

The rate limit counter wasn't being updated on failed requests,
which could lead to hitting the limit faster than expected when
there are network issues.

Fixes #42
```

## What We Need Help With

Some areas where contributions would be especially welcome:

- **Keyring integration** - storing tokens securely instead of plaintext
- **Media uploads** - rupload flow for Instagram photos/voice
- **Better error handling** - more specific error messages to users
- **Tests** - unit tests, integration tests, anything really
- **Windows testing** - most dev happens on Linux
- **Documentation** - always room for improvement

## Updating Instagram/Messenger Endpoints

Meta changes their APIs periodically. If you notice something's broken:

1. Check if the endpoints in `config/meta-config.json` are still valid
2. Use browser dev tools or a proxy to capture current traffic
3. Update the config defaults and/or hardcoded values
4. Document what changed and when

## Questions?

Open an issue if you're not sure about something. We'd rather answer questions than miss out on a contribution because something wasn't clear.

## License

By contributing, you agree that your contributions will be licensed under the GPL-3.0 license (same as the project).