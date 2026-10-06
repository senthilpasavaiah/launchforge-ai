# LaunchForge AI

AI-assisted MVP and business app development.

## Portfolio
- Agency landing page at repository root
- FlowPilot AI demo at /demo/
- Transparent case study at /case-study/

Built as a static zero-paid-dependency launch site suitable for GitHub Pages.

## Private admin outreach

The public site's design and pages are preserved. A separate server now supports `/admin/outreach`, direct Gmail connection, lead qualification, owner-reviewed drafts, durable scheduling, inbox and suppression. Gmail is the default and needs no purchased domain. The optional Mailgun adapter remains available for domain email. Client accounts cannot access the outreach UI or APIs. GitHub Pages cannot execute this backend; deploy it on a persistent HTTPS host using the included Docker/Compose setup.

Read [outreach setup and operations](outreach/OPERATIONS.md). Gmail sending remains disabled until the actual Google OAuth credentials, owner authorization and hosting are configured. Domain/DNS verification is only required if choosing Mailgun instead. Run `python -m unittest outreach.tests -v` for security, Gmail OAuth/API and queue tests.
