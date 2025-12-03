# libpurple-meta Quick Start Guide

This should get you chatting on Instagram or Messenger through Pidgin in about 5 minutes. If you run into issues, check the full [Configuration Guide](CONFIGURATION.md).

---

## Instagram Setup

### 1. Build & Install

**On Linux (Debian/Ubuntu):**
```bash
# grab the dependencies first
sudo apt install pidgin-dev libglib2.0-dev libjson-glib-dev

cd libpurple-meta
meson setup build
meson compile -C build
sudo meson install -C build
```

**On Windows:**
Grab the DLL from the Releases page and drop it in:
```
C:\Program Files\Pidgin\plugins\prpl-meta.dll
```

### 2. Add Your Account

Open Pidgin:
1. Go to **Accounts → Manage Accounts → Add**
2. Pick **Meta (Messenger + Instagram)** from the dropdown
3. Put in your Instagram username
4. Click the **Advanced** tab and configure:
   - **Service**: Select `Instagram DMs`
   - **Enable Instagram**: Check this box
   - **Instagram: Max API calls per hour**: `50` (conservative, avoids bans)
   - **Instagram: Min request interval (ms)**: `500` (or higher to be safe)
5. Hit **Add**

> **Tip:** All configuration is now available in the account settings UI - no need to edit JSON files!

### 3. Log In

Enable the account and you should get a login prompt. If you have 2FA enabled (you should!), you'll need to enter your code.

Instagram might throw a security challenge at you the first time - just follow the prompts.

---

## Messenger Setup

### 1. Get a Meta Developer App ID

You need to register an app with Meta first (yeah, it's annoying):

1. Head to [developers.facebook.com](https://developers.facebook.com/)
2. Create a new app - pick "Business" type
3. Add Messenger to your app
4. Copy your **App ID** somewhere
5. In settings, add `https://localhost/oauth/callback` as a valid redirect URI

See the [Meta App Setup Guide](META_APP_SETUP.md) for detailed instructions.

### 2. Add Your Account

1. **Accounts → Manage Accounts → Add** in Pidgin
2. Pick **Meta (Messenger + Instagram)**
3. Use your Facebook email as username
4. Click the **Advanced** tab and configure:
   - **Service**: Select `Facebook Messenger`
   - **Meta App ID (for Messenger)**: Paste your App ID here
   - **Enable Messenger**: Check this box
5. Click **Add**

> **Note:** The App ID is now entered directly in Pidgin's account settings - no JSON file needed!

### 4. Authorize

When you enable the account, your browser will pop up asking you to log into Facebook and authorize the app. Do that and you're good to go.

---

## Common Problems

| What's happening | What to do |
|------------------|------------|
| "Instagram disabled" error | Add `"instagram_enabled": true` to your config |
| Getting rate limited | Bump up `min_request_interval_ms` to 1000 or higher |
| Connection keeps timing out | Check your internet, or just wait and try again |
| Asking for 2FA | Log into the actual Instagram/FB app first and complete any challenges there |
| "Token invalid" errors | Delete the account in Pidgin, add it again fresh |

---

## Heads Up

⚠️ **Your tokens are stored in plaintext** in `~/.purple/accounts.xml`. Use full disk encryption if you're worried about that.

⚠️ **Instagram's API isn't official** - they might throw security challenges at you or temporarily block your account if you're too aggressive.

⚠️ **Don't spam requests** - keep the rate limits conservative or you'll get soft-banned.

---

## What Next?

If things aren't working right, check the [Configuration Guide](CONFIGURATION.md) for all the options. You can also turn on debug mode to see what's going wrong:

```json
{ "debug_mode": true }
```

Check **Help → Debug Window** in Pidgin to see the output.