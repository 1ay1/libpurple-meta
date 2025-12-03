# Meta App Setup Guide

This guide walks you through setting up a Meta Developer App to use with the libpurple-meta plugin for Pidgin. This is required because Meta's APIs require OAuth authentication with a registered application.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Step 1: Create a Meta Developer Account](#step-1-create-a-meta-developer-account)
4. [Step 2: Create a New App](#step-2-create-a-new-app)
5. [Step 3: Configure Your App](#step-3-configure-your-app)
6. [Step 4: Add Test Users](#step-4-add-test-users)
7. [Step 5: Get Your App Credentials](#step-5-get-your-app-credentials)
8. [Step 6: Configure the Plugin](#step-6-configure-the-plugin)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

---

## Overview

The libpurple-meta plugin uses Meta's official OAuth 2.0 API to authenticate with Instagram and Facebook Messenger. To use this plugin, you need to:

1. Create a Meta Developer App with the appropriate use case
2. Add your account as a test user
3. Configure the plugin with your App ID

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

Meta now uses a **use case-based** app creation flow. Follow these steps:

1. Go to [My Apps](https://developers.facebook.com/apps/)

2. Click **"Create App"**

3. You'll see a list of use cases. On the left sidebar, you can filter by category:
   - Featured
   - All
   - Ads and monetization
   - Content management
   - **Business messaging** ← For Messenger
   - Others

### For Instagram DMs:

4. Select **"Manage messaging & content on Instagram"**
   
   > This use case allows you to: Publish posts, share stories, respond to comments, answer direct messages and more with the Instagram API.

5. Click **"Next"**

### For Facebook Messenger:

4. Select **"Engage with customers on Messenger from Meta"**
   
   > This use case allows you to: Respond to messages sent to your business' Facebook Page. You can set up automatic replies or use a human agent to respond.

5. Click **"Next"**

### For Both Instagram and Messenger:

Unfortunately, Meta notes that "Some use cases can't be combined on the same app." You may need to:
- Create one app for Instagram
- Create a separate app for Messenger
- Or select Instagram (which is more commonly needed for personal use)

### Complete App Creation:

6. Fill in the app details:
   - **App Name:** Choose something like "My Pidgin Client" or "Personal IM Bridge"
   - **App Contact Email:** Your email address
   - **Business Portfolio:** Select "I don't want to connect a business portfolio" (unless you have one)

7. Click **"Create App"**

8. Complete any security checks (CAPTCHA, password confirmation)

---

## Step 3: Configure Your App

After creating your app, you need to configure OAuth settings.

### Configure OAuth Redirect URIs

1. In your app dashboard, go to **App Settings** → **Basic** (in the left sidebar)

2. Scroll down to find platform settings, or go to **Products** in the sidebar

3. Look for **Instagram** or **Messenger** settings depending on your use case

4. Find the OAuth or Redirect URI settings and add:
   ```
   https://localhost/oauth/callback
   ```

5. If there are fields for Deauthorize or Data Deletion URLs, add:
   ```
   https://localhost/oauth/deauthorize
   https://localhost/oauth/delete
   ```

6. Click **"Save Changes"**

### Note on the New Flow

With the use case-based flow, many settings are pre-configured based on your selected use case. You may find that:
- Required permissions are already added
- API access is already configured
- You just need to add test users and get your App ID

---

## Step 4: Add Test Users

Until your app is approved by Meta, only test users can authenticate. This is the most important step!

### For Instagram:

1. In your app dashboard, look for **App Roles** → **Roles** in the left sidebar

2. Find the section for **Instagram Testers** or **People**

3. Click **"Add People"** or **"Add Instagram Testers"**

4. Enter the Instagram username you want to add

5. **The user must accept the invitation:**
   - Open Instagram (app or web)
   - Go to **Settings** → **Apps and Websites** (or **Website Permissions**)
   - Find **"Tester Invites"**
   - Accept the pending invitation from your app

### For Messenger:

1. Go to **App Roles** → **Roles**

2. Add yourself as a **Tester** or **Developer**

3. Accept any pending invitations in your Facebook settings

### Verify Test User Status

- The invitation must be **accepted** before you can authenticate
- Check that the user shows as "Accepted" in your app's Roles page
- If you don't see the invitation in Instagram, try:
  - Logging out and back in to Instagram
  - Checking on the Instagram mobile app instead of web
  - Waiting a few minutes for the invitation to appear

---

## Step 5: Get Your App Credentials

1. In your app dashboard, go to **App Settings** → **Basic**

2. At the top, you'll see your **App ID** - this is a numeric string like `123456789012345`

3. Copy the **App ID** (this is what you need for the plugin config)

4. You'll also see an **App Secret** - keep this private! (The plugin typically only needs the App ID)

   > **Security Note:** The App Secret should NEVER be shared or committed to version control.

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
- **Fix:** Double-check the App ID in `~/.purple/meta-config.json` matches your app dashboard exactly (should be numbers only)

### "App Not Set Up" or "App Configuration Error"

- **Cause:** The use case permissions aren't properly configured
- **Fix:** 
  1. Go to your app dashboard
  2. Check that the Instagram or Messenger product is properly set up
  3. Ensure OAuth redirect URIs are configured

### "User Not Authorized" or "User is not a tester"

- **Cause:** Your Instagram/Facebook account isn't added as a test user, or the invitation wasn't accepted
- **Fix:** 
  1. Complete Step 4 above
  2. Make sure to **accept the invitation** in Instagram Settings → Apps and Websites → Tester Invites
  3. Wait a few minutes after accepting before trying again

### "Redirect URI Mismatch"

- **Cause:** The redirect URI in your config doesn't match what's registered in the app
- **Fix:** Ensure `https://localhost/oauth/callback` is listed in your app's OAuth Redirect URIs

### Browser Opens But Login Fails

1. Check Pidgin's debug log: **Help** → **Debug Window**
2. Look for lines starting with `prpl-meta:` for error details
3. Ensure you're logging into the correct Instagram/Facebook account (the one added as a tester)

### Can't Find Tester Invites in Instagram

Try these locations:
- **Mobile App:** Settings → Security → Apps and Websites → Tester Invites
- **Web:** Settings → Apps and Websites → Tester Invites
- **Alternative:** Settings → Privacy → Apps and Websites

If still not visible:
- Log out and back in to Instagram
- Try on a different device
- Wait 10-15 minutes for the invitation to propagate

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

**A:** It depends on the use cases you selected. With the new flow, some use cases can't be combined. You may need separate apps for each service.

### Q: Is my App Secret needed?

**A:** The plugin uses a client-side OAuth flow that primarily needs only the App ID. The App Secret is used server-side and should be kept private.

### Q: How many test users can I add?

**A:** You can add up to 100 test users during development.

### Q: Why are some use cases grayed out?

**A:** Meta has restrictions on combining certain use cases. Options like "Facebook Login" and "Launch a game on Facebook" are disabled when you select Instagram messaging. This is normal - select only what you need.

### Q: Will this stop working?

**A:** Meta occasionally updates their API. The plugin's configuration system allows updating endpoints without rebuilding the plugin. Check for config updates if things stop working.

### Q: Can I use this for a business/brand account?

**A:** Yes, but you may need to:
1. Connect a Business Portfolio to your app
2. Select business-focused use cases
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
| Instagram Use Case | "Manage messaging & content on Instagram" |
| Messenger Use Case | "Engage with customers on Messenger from Meta" |

---

*Last updated: 2025*