# The Foundry on Netlify

This folder is ready to deploy. It gives you:

- real sign-in (passwords are hashed on the server)
- **Users and access**: invite real email addresses by role; the platform emails each person a one-time link
- creator self-registration
- one shared set of data, so admins, panelists, sponsors and creators all see the same live platform

## 1. Put it on Netlify

Netlify's drag-and-drop box does not install the function's package, so use one of these:

**Option A: GitHub (easiest)**
1. Create a GitHub repository and upload everything in this folder.
2. In Netlify choose *Add new site → Import an existing project*, pick the repository. Build settings are read from `netlify.toml`.

**Option B: Netlify CLI**
```
npm install
npx netlify-cli login
npx netlify-cli deploy --prod
```

## 2. Set these environment variables
Netlify → Site configuration → Environment variables. Then redeploy.

| Name | What to put |
|---|---|
| `SESSION_SECRET` | A long random string (30+ characters). Keep it private. |
| `ADMIN_EMAIL` | Your email. This becomes the first Super admin. |
| `ADMIN_PASSWORD` | The password for that first sign-in. Change nothing else needed; it is hashed on first use. |
| `RESEND_API_KEY` | API key from resend.com (free tier is fine). |
| `FROM_EMAIL` | e.g. `The Foundry <invites@yourdomain.com>`. The domain must be verified in Resend. |
| `SITE_URL` | Optional. Your site address, e.g. `https://foundry.africa`. Defaults to the address the admin is on. |

If email is not configured, invitations still work: the admin sees the personal link on the Users and access page and can send it by hand.

## 3. First sign-in
Open your site → Sign in → **Team** tab → use `ADMIN_EMAIL` and `ADMIN_PASSWORD`. Go to **Users and access**, pick a role, enter the person's name and email, and press *Create invitation*.

## Good to know
- Data is stored in Netlify Blobs (nothing else to set up).
- Two people editing the same record at the same second: the later save is refused and the screen refreshes with the latest data. Rare at this scale.
- Blind review and role limits are enforced by the app screens, not by the database. That is fine for a pilot with invited, trusted people. Before opening it widely, move each role's rules onto the server.
- There is no password reset yet. An admin can revoke a person and invite them again.
