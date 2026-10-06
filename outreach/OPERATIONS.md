# ForgeLaunch private Outreach

## Current configuration: your existing Gmail

Gmail is now the default (`EMAIL_PROVIDER=gmail`). You do **not** need a purchased domain, Mailgun account, or SPF/DKIM/DMARC changes to use your existing `@gmail.com` mailbox. The Mailgun-specific section below is retained only for an optional future domain-email configuration.

The application connects directly to Google through OAuth; it cannot reuse ChatGPT Gmail connector permissions. Only the signed-in Senthil owner can connect or disconnect the mailbox. Google receives a state-bound, single-use authorization request with PKCE. The callback is tied to the initiating owner session and browser, and checks the actual Gmail account against `GMAIL_ALLOWED_EMAIL` before accepting credentials. Read-only mailbox and send permissions are requested; deleting emails and modifying Gmail labels are not requested.

### Gmail activation

1. Sign into your own [Google Cloud console](https://console.cloud.google.com/), create/select the ForgeLaunch project, and enable **Gmail API**. Configure Google Auth Platform consent, adding the `gmail.send` and `gmail.readonly` scopes. For an external app in Testing, explicitly add your Gmail address as a test user.
2. Create an OAuth client of type **Web application**. Add the exact authorized redirect URI `PUBLIC_ORIGIN/auth/gmail/callback`. The actual hosting provider's HTTPS address is sufficient; it does not need to be a purchased domain. For local development only, use `http://127.0.0.1:8080/auth/gmail/callback` and the same origin configured on the loopback server.
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GMAIL_ALLOWED_EMAIL` (your exact mailbox), `PUBLIC_ORIGIN`, `UNSUBSCRIBE_SECRET` and `AI_SERVICE_TOKEN` in the server's private environment. Set `EMAIL_PROVIDER=gmail`. Domain verification and Mailgun flags do not apply to Gmail. Keep `EMAIL_ENABLED=false` while testing.
4. Deploy the web and worker services using the persistent HTTPS hosting instructions below, create Senthil's owner login, then sign in → Email setup → **Connect Gmail**. Select the configured Google account and approve permissions on Google's page. No Gmail password is entered into ForgeLaunch. Until client credentials exist, the Connect button is disabled and the app explains the pending setup; no fake authorization link is provided.
5. Send an owner-approved message to your own consenting test mailbox, reply, and use **Sync replies**. After live verification, set `EMAIL_ENABLED=true`. The worker syncs replies independently of the Gulf sending window, including Friday.

Google OAuth apps in **Testing** normally receive refresh tokens expiring after seven days for these scopes. Do not promise continuous daily operation with Testing credentials. Configure the appropriate published/personal-use consent status and satisfy Google's current verification requirements before long-term use. Tokens can also be revoked or invalidated by Google/user policy. The app automatically refreshes access tokens, displays `reconnect_required` when access is revoked, and preserves the queue for the owner to reconnect. A one-time grant does not guarantee permanent access.

The connected refresh/access tokens are stored only in the server database and never returned by any UI/API. Run the host with an encrypted disk and restrict the persistent volume and backups to the application/host owner. Linux files are created with an owner-only umask. The database now contains Google credentials as well as message data; restrict and encrypt backups accordingly. Do not publish/download it as a build artifact. **Disconnect Gmail** removes the stored credentials and attempts Google revocation; if remote revocation fails, the UI/API advises removing the app in Google Account permissions.

Reply synchronization checks only stored ForgeLaunch outreach threads and imports only mail from the corresponding lead. Unrelated conversations are not copied into the app, although Google's read-only scope technically allows mailbox reading. Gmail permanent delivery-status emails are accepted as bounces only when the original ForgeLaunch Message-ID and recipient match; unrelated notifications are ignored. Gmail does not supply Mailgun-style delivered/read/complaint webhooks. Sending means Google accepted the message, not that a client received or read it. Automated opt-outs and matched permanent bounces still suppress further sends.

Unknown send outcomes are reconciled through Gmail Sent using a stable RFC Message-ID; no blind resend occurs. The worker polls tracked threads in batches, periodically wrapping through them. Gmail sending/API quotas still apply; the app's conservative daily cap does not override Google's limits. Research/approval, suppression, client isolation and commercial-term gates remain enforced.

References: [Google OAuth web-server flow](https://developers.google.com/identity/protocols/oauth2/web-server), [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes), [Gmail send API](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/send).

The existing repository is a static GitHub Pages site. Public pages and assets are preserved. This addition runs a private WSGI API, SQLite database on a persistent disk, and a separate durable email worker. It cannot run on GitHub Pages. No real email has been sent, no production credentials are included, and no prospect data has been imported from the public business files.

## Deployment

Use a Linux Docker host with HTTPS and a persistent volume. Keep the current public site at its existing address and point a dedicated admin hostname to this host, or route `/admin`, `/api/outreach`, `/auth`, `/webhooks` and `/unsubscribe` to this service from the existing reverse proxy. Keep the UI and API on the same origin. Do not deploy on an ephemeral/serverless filesystem. Do not use `python -m http.server` to serve this repository: it would expose private/source files.

1. Copy `.env.example` to `.env` on the server and populate it through your secret manager. `PUBLIC_ORIGIN` must be the exact HTTPS origin with no trailing slash. `OUTREACH_DB=/data/outreach.sqlite`. Do not set `LOCAL_DEV` in production.
2. Generate separate cryptographically random secrets of at least 32 characters for `UNSUBSCRIBE_SECRET` and `AI_SERVICE_TOKEN`. Keep unsubscribe secrets stable so old links still work. Rotate the service token separately. Create no shared passwords for workers.
3. Run `docker compose build` and `docker compose run --rm web python -m outreach.manage create-owner --email SENTHIL_EMAIL`. Enter Senthil's actual chosen password interactively; it must have at least 16 characters. The CLI permits only one owner. No production account or password has been invented.
4. Run `docker compose up -d`. Terminate TLS at your existing reverse proxy, forward to `127.0.0.1:8080`, limit request bodies to 2 MB, and preserve `Origin`. Only the reverse proxy should be publicly exposed. Set a restrictive trusted proxy/IP rate limit on `/auth/login` in addition to the app limiter. SQLite is for this single-host deployment; do not scale containers onto independent hosts/disks.
5. Verify `/health`, sign in at `/admin/login`, check `/admin/outreach`, and confirm anonymous/client requests to `/api/outreach/state` return 403. Confirm the worker is running with `docker compose logs worker`. Configure your host monitor to alert on process exit, sustained queue backlog, `failed`/`uncertain` messages, and disk exhaustion.
6. Take a daily SQLite online backup (`sqlite3.Connection.backup` or the SQLite backup command), encrypt it in storage and restrict access to the host operator. Test restore before enabling email. Backups contain lead and message data. Do not copy a live SQLite file without its WAL. Apply a retention policy appropriate to your business.

The Compose processes restart on failure. Each due message has its own outcome. A provider configuration outage keeps the queue intact. Friday pauses sending but inbox/event processing stays active. The fixed Gulf schedule is UTC+4, Saturday–Thursday 09:00–17:00; there are at most 20 attempted sends/day, including uncertain requests and retries. It is not a promise that an external service will never fail.

## Mailgun and domain setup

Mailgun supplies domain email, incoming routes and signed delivery events without a ChatGPT Gmail connector. Use it only for recipients who agreed to receive your contact; record consent evidence for each lead. Website scraping or a publicly listed address does not establish consent. `PROVIDER_USE_APPROVED=true` records the operator's check that this specific use is permitted by the account and provider. First-contact messages remain human reviewed. The app sends no automated follow-ups.

Suggested architecture (only after confirming domain ownership): sending address `sales@forgelaunch.ai`, Mailgun domain `mg.forgelaunch.ai`, reply address `sales@inbox.forgelaunch.ai`. These are suggestions, not existing verified identities. Set `MAIL_FROM`, `MAILGUN_DOMAIN`, `MAIL_REPLY_TO` and `MAILGUN_REGION` to the actual configuration. Mailgun must authorize the chosen From domain. If using a sending subdomain for From, use its actual address instead. Keep current website and root-domain mail records intact.

| DNS purpose | Action |
| --- | --- |
| Domain ownership / DKIM | Copy the exact verification and DKIM TXT/CNAME records issued for your domain by Mailgun. Do not invent selectors or keys. |
| SPF | Add/merge the provider-issued SPF record at the instructed sending/return-path hostname. Publish only one SPF TXT record per hostname; include existing senders and respect the SPF lookup limit. |
| DMARC | Add `_dmarc` at the applicable organizational/sending domain. Begin with `v=DMARC1; p=none` and add an owned, monitored reporting address if available. Validate SPF or DKIM alignment before moving to quarantine/reject. Do not replace an existing DMARC policy blindly. |
| Incoming replies | Add provider-issued MX records only for the dedicated `inbox` subdomain. Do not overwrite existing root-domain MX records. |
| Admin host | Point the selected private admin hostname to the backend host; provision a valid TLS certificate. |

Set `MAILGUN_API_KEY` to a domain-scoped sending key and `MAILGUN_SIGNING_KEY` to the separate webhook signing key. Configure accepted, delivered, permanent/temporary failure, complaint and unsubscribe webhooks at `https://ADMIN_HOST/webhooks/mailgun/events`. Configure a Mailgun inbound route matching the exact `MAIL_REPLY_TO`, using `forward("https://ADMIN_HOST/webhooks/mailgun/inbound")` and `stop()`. This endpoint accepts the documented URL-encoded or multipart forwarding format; do not append `json` or `mime` to the destination. Attachments are intentionally discarded; inbox displays plain text only.

After Mailgun verifies the actual domain and confirms permitted use, test an email to your own consenting mailbox, reply to it, and exercise delivery/bounce events. Then set `DOMAIN_VERIFIED=true`, `PROVIDER_USE_APPROVED=true`, `EMAIL_ENABLED=true`. The three switches default to false. The credentials and live DNS must be supplied by the domain/account owner; code tests cannot verify them.

Primary references: [Mailgun webhook signatures](https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/securing-webhooks), [incoming route formats](https://documentation.mailgun.com/docs/mailgun/user-manual/receive-forward-store/receive-http), [Mailgun acceptable use](https://www.mailgun.com/legal/aup/).

## Permissions and operation

| Identity | Permissions |
| --- | --- |
| Senthil owner | View, research, draft, approve the exact message and any commercial terms, schedule, cancel, pause, suppress. |
| Admin | View, research/qualify and draft. Cannot approve, schedule or change sending settings. |
| AI/service bearer token | Submit leads and drafts, derive a draft from already-qualified research. Cannot read inbox/data, qualify consent, approve, schedule or send. |
| Client / anonymous | No outreach page or data API access. |

Service requests use `Authorization: Bearer AI_SERVICE_TOKEN` only on the server. Never embed the token in a browser or public file. The current research assistant creates a deterministic draft from recorded evidence; it does not call an AI model or claim it independently browsed/researched. Integrate an external AI worker using these restricted endpoints if required; every proposed message must still receive Senthil approval.

Add a lead → record source observations, contact verification and consent → generate or write draft → Senthil reviews exact text and commercial terms → schedule. The server rechecks approval content, suppression, duplicate first contacts and replies immediately before sending. Drafts cannot be mutated after approval through the API. Corrections require cancelling and writing a new draft.

The exact-content approval gate covers every message, so binding pricing, scope, delivery, contracts, refunds and payment terms cannot bypass Senthil approval even if keyword detection misses a paraphrase. An admin/service cannot self-promote or grant approval.

`429` provider rejections retry with increasing delay, shifted into Gulf business hours, up to five attempts. Other explicit 4xx failures become `failed`. Network timeouts, server 5xx and interrupted sends become `uncertain`: Mailgun may have accepted the email. There is intentionally no blind resend button. Check the provider event log using `outreach_id`/message ID and reconcile the database through a trusted host operator. Accepted/delivered webhooks can resolve an uncertain send. Permanent bounces, complaints and unsubscribe requests suppress the recipient and cancel pending outreach. Temporary delivery failures are left to Mailgun's redelivery, not duplicated by this worker.

## Local verification

`python -m unittest outreach.tests -v` uses temporary databases and a fake provider; no network or real sending occurs. For development use `LOCAL_DEV=true`, `PUBLIC_ORIGIN=http://127.0.0.1:8080`, create an owner interactively and run `python -m outreach.manage serve`. Never use these settings in production.

Production limitations: no external AI model configured, no attachment downloads, no purchased/scraped-list cold campaign sending, no automatic follow-ups, and no provider/DNS/hosting credentials included. Failed/uncertain records require operator review. Authentication is password-based with eight-hour HTTP-only sessions, CSRF checks and login throttling; add your host's MFA/identity gateway before granting additional operators access if required.
