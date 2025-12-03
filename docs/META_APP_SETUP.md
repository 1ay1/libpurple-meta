# Meta App Setup Guide

This guide walks you through setting up a Meta Developer App to use with the libpurple-meta plugin for Pidgin. This is required because Meta's APIs require OAuth authentication with a registered application.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Step 1: Create a Meta Developer Account](#step-1-create-a-meta-developer-account)
4. [Step 2: Create a New App](#step-2-create-a-new-app)
5. [Step 3: Configure Instagram Basic Display](#step-3-configure-instagram-basic-display)
6. [Step 4: Add Test Users](#step-4-add-test-users)
7. [Step 5: Get Your App Credentials](#step-5-get-your-app-credentials)
8. [Step 6: Configure the Plugin](#step-6-configure-the-plugin)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

---

## Overview

The libpurple-meta plugin uses Meta's official OAuth 2.0 API to authenticate with Instagram and Facebook Messenger. To use this plugin, you need to:

1. Create a Meta Developer App
2. Configure the appropriate API products (Instagram Basic Display, Messenger, etc.)
3. Add your account as a test user
4. Configure the plugin with your App ID

**Important:** Until your app passes Meta's App Review, only accounts added as "Test Users" can authenticate. This is fine for personal use.

---

## Prerequisites

- A Facebook account
- An Instagram account (linked to your Facebook account for best results)
- Pidgin with the libpurple-meta plugin installed

---

## Step 1: Create a Meta Developer Account

1. Go to [Meta for Developers](https://developers.facebook.com/)

2. Click **"Get Started"** or **"Log In"** in the top right

3. Log in with your Facebook account

4. If prompted, agree to the Meta Platform Terms and Developer Policies

5. Verify your account (phone number or other verification may be required)

---

## Step 2: Create a New App

1. Go to [My Apps](https://developers.facebook.com/apps/)

2. Click **"Create App"**

3. Select the app type:
   - For Instagram DMs: Choose **"Consumer"** or **"None"**
   - For Messenger: Choose **"Business"**
   
   > **Tip:** "Consumer" works for most personal use cases

4. Fill in the app details:
   - **App Name:** Choose something like "My Pidgin Client" or "Personal IM Bridge"
   - **App Contact Email:** Your email address
   - **Business Account:** Select "I don't want to connect a business portfolio" (unless you have one)

5. Click **"Create App"**

6. Complete any security checks (CAPTCHA, password confirmation)

---

## Step 3: Configure Instagram Basic Display

This section is for Instagram DM support. Skip to [Configure Messenger](#configure-messenger-optional) if you only want Facebook Messenger.

### Add the Instagram Basic Display Product

1. From your app's dashboard, find the **"Add Products"** section (or click **"Add Product"** in the left sidebar)

2. Find **"Instagram Basic Display"** and click **"Set Up"**

3. Scroll down to **"User Token Generator"** section

### Configure OAuth Settings

1. In the left sidebar, go to **Instagram Basic Display** → **Basic Display**

2. Under **"Valid OAuth Redirect URIs"**, add:
   ```
   https://localhost/oauth/callback
   ```

3. Under **"Deauthorize Callback URL"**, add:
   ```
   https://localhost/oauth/deauthorize
   ```

4. Under **"Data Deletion Request URL"**, add:
   ```
   https://localhost/oauth/delete
   ```

5. Click **"Save Changes"**

### Configure Messenger (Optional)

For Facebook Messenger support:

1. From your app's dashboard, click **"Add Product"**

2. Find **"Messenger"** and click **"Set Up"**

3. Follow the prompts to configure Messenger settings

---

## Step 4: Add Test Users

Until your app is approved by Meta, only test users can authenticate.

### For Instagram:

1. Go to **Instagram Basic Display** → **Basic Display** in your app dashboard

2. Scroll to **"User Token Generator"**

3. Click **"Add or Remove Instagram Testers"**

4. This opens Instagram settings. Under **"Apps and Websites"**, find **"Tester Invites"**

5. Accept the invitation for your app

### Alternative Method:

1. Go to **App Roles** → **Roles** in your app dashboard

2. Click **"Add People"** under "Instagram Testers"

3. Enter the Instagram username you want to add

4. The user must accept the invitation:
   - Go to Instagram → Settings → Apps and Websites → Tester Invites
   - Accept the pending invitation

---

## Step 5: Get Your App Credentials

1. In your app dashboard, go to **Settings** → **Basic**

2. Note down your **App ID** (this is public and goes in the config)

3. Note down your **App Secret** (keep this private!)

   > **Security Note:** The App Secret should NEVER be shared or committed to version control. For this plugin's client-side OAuth flow, you typically only need the App ID.

---

## Step 6: Configure the Plugin

### Copy the Configuration File

1. Copy the sample configuration file to your Purple directory:

   **On Linux/macOS:**
   ```bash
   cp config/meta-config.json ~/.purple/meta-config.json
   ```

   **On Windows:**
   Copy `config\meta-config.json` to `C:\Users\<YourUsername>\AppData\Roaming\.purple\meta-config.json`

2. Open the config file in a text editor:

   **On Linux/macOS:**
   ```bash
   nano ~/.purple/meta-config.json
   ```

   **On Windows:**
   Open with Notepad or your preferred editor

3. Find this line in the `messenger` section:
   ```json
   "oauth_client_id": "YOUR_META_APP_ID_HERE",
   ```

4. Replace `YOUR_META_APP_ID_HERE` with your actual App ID from Step 5:
   ```json
   "oauth_client_id": "123456789012345",
   ```

5. Save the file

### Verify Configuration

1. Restart Pidgin (close completely and reopen)

2. Go to **Accounts** → **Manage Accounts** → **Add**

3. Select **"Meta (Messenger + Instagram)"** as the protocol

4. Enter your Instagram/Facebook username

5. Click **Add** - a browser window should open to Meta's login page

6. Log in with the account you added as a test user in Step 4

7. After authenticating, you should be redirected and the plugin will capture the token

---

## Troubleshooting

### "Invalid App ID"

- **Cause:** The App ID in your config doesn't match a valid Meta app
- **Fix:** Double-check the App ID in `~/.purple/meta-config.json` matches your app dashboard

### "App Not Set Up"

- **Cause:** The Instagram Basic Display product isn't configured
- **Fix:** Complete Step 3 above, ensuring you've added the OAuth redirect URIs

### "User Not Authorized"

- **Cause:** Your Instagram account isn't added as a test user
- **Fix:** Complete Step 4 above and accept the tester invitation in Instagram settings

### "Redirect URI Mismatch"

- **Cause:** The redirect URI in your config doesn't match what's registered in the app
- **Fix:** Ensure `https://localhost/oauth/callback` is listed in your app's Valid OAuth Redirect URIs

### Browser Opens But Login Fails

1. Check Pidgin's debug log: **Help** → **Debug Window**
2. Look for lines starting with `prpl-meta:` for error details
3. Ensure you're logging into the correct Instagram/Facebook account (the one added as a tester)

### "Session Expired" or Token Errors

Instagram tokens expire after 60 days. To refresh:

1. Go to Pidgin → Accounts → Manage Accounts
2. Select your Meta account
3. Click "Re-authenticate" from the account actions menu

---

## FAQ

### Q: Do I need to submit my app for review?

**A:** No, not for personal use. Test users can authenticate without app review. App review is only needed if you want other people (non-test users) to use your app.

### Q: Can I use the same App ID for both Instagram and Messenger?

**A:** Yes! One Meta app can have multiple products enabled.

### Q: Is my App Secret needed?

**A:** The plugin uses a client-side OAuth flow that primarily needs only the App ID. The App Secret is used server-side and should be kept private.

### Q: How many test users can I add?

**A:** You can add up to 100 test users during development.

### Q: Will this stop working?

**A:** Meta occasionally updates their API. The plugin's configuration system allows updating endpoints without rebuilding the plugin. Check for config updates if things stop working.

### Q: Can I use this for a business/brand account?

**A:** Yes, but you may need to:
1. Connect a Business Portfolio to your app
2. Use different API products (Instagram Messaging API instead of Basic Display)
3. Complete additional verification steps

---

## Security Notes

1. **Never share your App Secret** - It's not needed for this plugin anyway

2. **App ID is public** - It's safe to have in your config file, but don't share it unnecessarily

3. **Tokens are stored locally** - The plugin stores OAuth tokens in `~/.purple/`. Ensure this directory has appropriate permissions (readable only by you)

4. **Use strong Facebook password** - Your Meta app has access to your messaging, so protect your Facebook account

---

## Getting Help

- **Plugin Issues:** Check the [GitHub Issues](https://github.com/user/libpurple-meta/issues)
- **Meta API Issues:** See [Meta Developer Documentation](https://developers.facebook.com/docs/)
- **Pidgin Issues:** Visit [Pidgin Support](https://pidgin.im/support/)

---

## Quick Reference

| Setting | Value |
|---------|-------|
| Config File Location | `~/.purple/meta-config.json` |
| OAuth Redirect URI | `https://localhost/oauth/callback` |
| Instagram Scopes | `instagram_basic,instagram_manage_messages` |
| Messenger Scopes | `pages_messaging,pages_read_engagement` |

---

*Last updated: 2025*