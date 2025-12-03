# Meta App Setup Guide

This guide walks you through setting up a Meta Developer App to use with the libpurple-meta plugin for Pidgin. This is required because Meta's APIs require OAuth authentication with a registered application.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Step 1: Create a Meta Developer Account](#step-1-create-a-meta-developer-account)
4. [Step 2: Create a New App](#step-2-create-a-new-app)
5. [Step 3: Configure Basic Settings](#step-3-configure-basic-settings)
6. [Step 4: Add Platform Settings](#step-4-add-platform-settings)
7. [Step 5: Add Test Users](#step-5-add-test-users)
8. [Step 6: Get Your App Credentials](#step-6-get-your-app-credentials)
9. [Step 7: Configure the Plugin](#step-7-configure-the-plugin)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)

---

## Overview

The libpurple-meta plugin uses Meta's official OAuth 2.0 API to authenticate with Instagram and Facebook Messenger. To use this plugin, you need to:

1. Create a Meta Developer App with the appropriate use case
2. Configure the app's Basic Settings
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

Meta uses a **use case-based** app creation flow. Navigate to the app creation page and follow these steps:

1. Go to [App Creation](https://developers.facebook.com/apps/creation/) or navigate to [My Apps](https://developers.facebook.com/apps/) and click **"Create App"**

2. **App Details:** Enter your app's name (e.g., "My Pidgin Client" or "Personal IM Bridge") and a contact email address, then click **Next**

3. **Use Cases:** Select one or more use cases for your app:

   ### For Instagram DMs:
   Select **"Manage messaging & content on Instagram"**
   > This use case allows you to: Publish posts, share stories, respond to comments, answer direct messages and more with the Instagram API.

   ### For Facebook Messenger:
   Select **"Engage with customers on Messenger from Meta"**
   > This use case allows you to: Respond to messages sent to your business' Facebook Page.

   ### Important Notes on Use Cases:
   - **Incompatible use cases are greyed out** when you select one
   - **Use cases cannot be removed** after app creation
   - You can add compatible use cases later, but only compatible ones will be displayed
   - Some products like Facebook Login for Business and Webhooks may be automatically added

4. **Business Portfolio:** Select one of these options:
   - A verified business portfolio
   - An unverified business portfolio  
   - **"I don't want to connect a business portfolio yet"** ← Recommended for personal use
   - Create a business portfolio

5. **Requirements:** Review any requirements for your selected use cases (like App Review for production access)

6. **Overview:** Review your app's details, then click **"Go to dashboard"**

---

## Step 3: Configure Basic Settings

After creating your app, you'll be taken to the App Dashboard. Navigate to **App Settings** → **Basic** in the left sidebar to configure your app.

### Basic Settings Fields

The Basic Settings page contains these important fields:

| Field | Description | Required |
|-------|-------------|----------|
| **App ID** | Your unique app identifier (auto-generated, read-only) | Auto |
| **App secret** | Secret key for server-side authentication (click "Show" to reveal) | Auto |
| **Display name** | The name shown to users during authentication | Yes |
| **Namespace** | URL-safe identifier for your app (optional) | No |
| **App domains** | Domains where your app is hosted | For OAuth |
| **Contact email** | Email for important Meta communications (shows required indicator) | Yes |
| **Privacy policy URL** | Link to your privacy policy (required for going live) | For Review |
| **Terms of Service URL** | Link to your terms of service | No |
| **User data deletion** | How users can request data deletion (URL or instructions) | For Review |
| **App icon** | 1024x1024 icon for your app | No |
| **Category** | App category classification | No |

### Configure Required Fields

1. **Display name:** Enter a user-friendly name (e.g., "purple" or "Pidgin Meta Client")

2. **Contact email:** Ensure this is a valid email you monitor

3. **App domains:** Add `localhost` for OAuth callback:
   - Type `localhost` in the App domains field and press Enter

4. **User data deletion:** You have two options in the dropdown:
   
   - **Option A (Recommended):** Select **"Data deletion instructions"** and enter:
     ```
     To delete your data, remove the account from Pidgin (Accounts → Manage Accounts → Delete), 
     then delete ~/.purple/accounts.xml and ~/.purple/meta-config.json. 
     No data is stored on any server by this plugin.
     ```
   
   - **Option B:** Select **"Data deletion callback URL"** and enter a valid URL you control.
     (Note: `https://localhost/...` URLs will fail validation since Meta cannot reach them)

5. Click **"Save changes"** at the bottom of the page

### Data Protection Officer (Optional)

The Basic Settings page also includes a section for **Data Protection Officer contact information** for GDPR compliance. This is optional for personal use but includes fields for:
- Name
- Email
- Address (Street, City, State, ZIP, Country)

---

## Step 4: Add Platform Settings

At the bottom of the Basic Settings page, you can add platform-specific settings. Click **"Add platform"** to see options:

### For Web/OAuth (Required for this plugin):

1. Click **"Add platform"**
2. Select **"Website"**
3. In the Website section that appears, you'll see:
   - **Site URL:** Enter the URL of your site. For this plugin, enter:
     ```
     https://localhost
     ```
   - **Quick Start** link (optional - links to Meta's setup documentation)
   
4. **Provide testing instructions:** Meta performs regular reviews of apps to verify permission access follows their terms and policies. You'll see a note:
   > "Meta performs regular reviews of apps on the platform in order to verify that an app's access to permissions follows our terms and policies. Avoid unexpected restrictions by keeping this required testing information up to date."
   
   Click **"Add or update instructions"** if you plan to submit for App Review. For personal use with test users only, you can skip this.

5. Click **"Save changes"**

### Other Platform Options (Optional):

The dashboard also supports:
- **iOS** - Bundle ID, iPhone/iPad Store IDs, URL Scheme Suffix, Shared secret
- **Android** - Key hashes, Google Play Store settings, In-App Purchase logging
- **Xbox** - Xbox title IDs
- **PlayStation** - PlayStation title IDs
- **Windows app** - Windows 10 App Store URL, Windows Store SID, Windows Phone Store SID
- **Page Tab** - Secure Page Tab URL, Page Tab name, edit URL, and image
- **Instant Game** - Instant Game link (uses namespace: fb.gg/play/[namespace])

For libpurple-meta, you typically only need the **Website** platform configured.

> **Note:** Each platform section includes a "Provide testing instructions" option and can be removed via the close/remove button if added by mistake.

---

## Step 5: Add Test Users

Until your app passes Meta's App Review, only test users can authenticate. This is the most important step!

### Navigate to App Roles

1. In the left sidebar, go to **App Roles** → **Roles**

### For Instagram:

1. Find the section for **Instagram Testers** or look for an **"Add People"** button

2. Click **"Add Instagram Testers"**

3. Enter the Instagram username you want to add

4. **The user must accept the invitation:**
   - Open Instagram (app or web)
   - Go to **Settings** → **Apps and Websites** (or **Website Permissions**)
   - Look for **"Tester Invites"** section
   - Accept the pending invitation from your app

### For Messenger/Facebook:

1. Go to **App Roles** → **Roles**

2. Add yourself as a **Tester** or **Developer**:
   - Click **"Add People"**
   - Enter the Facebook user's name or ID
   - Select the appropriate role

3. The user must accept the invitation via Facebook notification or in Facebook Settings

### Verify Test User Status

- The invitation must be **accepted** before you can authenticate
- Check that the user shows as "Accepted" in your app's Roles page
- You can have up to **100 test users** during development

---

## Step 6: Get Your App Credentials

1. In your app dashboard, go to **App Settings** → **Basic**

2. At the top of the page, you'll see:
   - **App ID:** A numeric string like `1382377013272260` (visible, read-only)
   - **App secret:** Hidden by default - click **"Show"** button to reveal

3. Copy the **App ID** - this is what you need for the plugin config

4. **Security Note:** The App Secret should NEVER be shared or committed to version control. The plugin typically only needs the App ID for client-side OAuth.

---

## Step 7: Configure the Plugin

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

4. Replace `YOUR_META_APP_ID_HERE` with your actual App ID from Step 6:
   ```json
   "oauth_client_id": "1382377013272260",
   ```

5. Save the file

### Verify Configuration

1. Restart Pidgin (close completely and reopen)

2. Go to **Accounts** → **Manage Accounts** → **Add**

3. Select **"Meta (Messenger + Instagram)"** as the protocol

4. Enter your Instagram/Facebook username

5. Click **Add** - a browser window should open to Meta's login page

6. Log in with the account you added as a test user in Step 5

7. After authenticating, you should be redirected and the plugin will capture the token

---

## Troubleshooting

### "Invalid App ID"

- **Cause:** The App ID in your config doesn't match a valid Meta app
- **Fix:** Double-check the App ID in `~/.purple/meta-config.json` matches your app dashboard exactly (should be numbers only, no quotes issues)

### "App Not Set Up" or "App Configuration Error"

- **Cause:** The use case permissions aren't properly configured or platform not added
- **Fix:** 
  1. Go to **App Settings** → **Basic**
  2. Ensure you've added the Website platform with the correct Site URL
  3. Check that `localhost` is in App domains
  4. Click **"Save changes"**

### "User Not Authorized" or "User is not a tester"

- **Cause:** Your Instagram/Facebook account isn't added as a test user, or the invitation wasn't accepted
- **Fix:** 
  1. Complete Step 5 above
  2. Make sure to **accept the invitation** in Instagram Settings → Apps and Websites → Tester Invites
  3. Wait a few minutes after accepting before trying again

### "Redirect URI Mismatch"

- **Cause:** The redirect URI in your config doesn't match what's registered in the app
- **Fix:** 
  1. In Basic Settings, ensure `localhost` is in App domains
  2. In the Website platform settings, ensure Site URL is `https://localhost`

### Browser Opens But Login Fails

1. Check Pidgin's debug log: **Help** → **Debug Window**
2. Look for lines starting with `prpl-meta:` for error details
3. Ensure you're logging into the correct Instagram/Facebook account (the one added as a tester)

### Can't Find Tester Invites in Instagram

Try these locations:
- **Mobile App:** Settings → Security → Apps and Websites → Tester Invites
- **Web:** Settings → Apps and Websites → Tester Invites
- **Alternative:** Settings → Privacy → Apps and Websites
- **Professional accounts:** Settings → Business → Apps and Websites

If still not visible:
- Log out and back in to Instagram
- Try on a different device (mobile app often works better)
- Wait 10-15 minutes for the invitation to propagate

### "Session Expired" or Token Errors

Instagram tokens expire after 60 days. To refresh:

1. Go to Pidgin → Accounts → Manage Accounts
2. Select your Meta account
3. Click "Re-authenticate" from the account actions menu

### App Limit Reached

You can only have a developer or admin role on a maximum of **15 apps** not connected to a verified business. Solutions:
- Connect a verified business portfolio to existing apps
- Remove old/unused apps (archived apps count toward the limit)
- Remove yourself from apps you don't need access to

---

## FAQ

### Q: Do I need to submit my app for review?

**A:** No, not for personal use. Test users can authenticate without app review. App review is only needed if you want other people (non-test users) to use your app.

### Q: Can I use the same App ID for both Instagram and Messenger?

**A:** It depends on the use cases you selected during app creation. Some use cases are incompatible and cannot be combined. If you selected incompatible use cases, you may need separate apps for each service.

### Q: Is my App Secret needed?

**A:** The plugin uses a client-side OAuth flow that primarily needs only the App ID. The App Secret is used server-side and should be kept private.

### Q: How many test users can I add?

**A:** You can add up to 100 test users during development.

### Q: Why are some use cases greyed out?

**A:** Meta has restrictions on combining certain use cases. When you select one use case, incompatible options are automatically greyed out. This is normal - select only what you need.

### Q: What is the difference between App ID and App Secret?

**A:** 
- **App ID:** Public identifier for your app, safe to include in client-side code
- **App Secret:** Private key that should never be exposed, used for server-to-server communication

### Q: Will this stop working?

**A:** Meta occasionally updates their API. The plugin's configuration system allows updating endpoints without rebuilding the plugin. Check for config updates if things stop working.

### Q: Can I use this for a business/brand account?

**A:** Yes, but you may need to:
1. Connect a Business Portfolio to your app during creation
2. Select business-focused use cases
3. Complete business verification if required

### Q: What is a Business Portfolio?

**A:** A business portfolio allows organizations to manage their Facebook Pages, Instagram accounts, ad accounts, and other business assets from one place using Meta Business Suite. It's optional for personal use.

---

## Security Notes

1. **Never share your App Secret** - It's not needed for this plugin anyway

2. **App ID is semi-public** - It's safe to have in your config file, but don't share it unnecessarily

3. **Tokens are stored locally** - The plugin stores OAuth tokens in `~/.purple/`. Ensure this directory has appropriate permissions (readable only by you):
   ```bash
   chmod 700 ~/.purple
   ```

4. **Use strong Facebook password** - Your Meta app has access to your messaging, so protect your Facebook account with a strong password and 2FA

5. **Review connected apps periodically** - In Instagram/Facebook Settings → Apps and Websites, review and remove apps you no longer use

---

## Getting Help

- **Plugin Issues:** Check the [GitHub Issues](https://github.com/libpurple-meta/libpurple-meta/issues)
- **Meta API Issues:** See [Meta Developer Documentation](https://developers.facebook.com/docs/)
- **App Creation Guide:** See [Create an App with Meta](https://developers.facebook.com/docs/development/create-an-app)
- **Pidgin Issues:** Visit [Pidgin Support](https://pidgin.im/support/)

---

## Quick Reference

| Setting | Value |
|---------|-------|
| Config File Location (Linux/macOS) | `~/.purple/meta-config.json` |
| Config File Location (Windows) | `%APPDATA%\.purple\meta-config.json` |
| Site URL (Website platform) | `https://localhost` |
| App Domains | `localhost` |
| Instagram Use Case | "Manage messaging & content on Instagram" |
| Messenger Use Case | "Engage with customers on Messenger from Meta" |
| App Creation URL | https://developers.facebook.com/apps/creation/ |
| Basic Settings Path | App Settings → Basic |
| Test Users Path | App Roles → Roles |

---

*Last updated: January 2025*