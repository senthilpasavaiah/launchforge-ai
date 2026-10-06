# LaunchForge AI

AI-assisted MVP and business app development.

## Portfolio
- Agency landing page at repository root
- FlowPilot AI demo at /demo/
- Transparent case study at /case-study/

Built as a static zero-paid-dependency launch site suitable for GitHub Pages.

## Private admin outreach

The public site's design and pages are preserved. A separate server now supports `/admin/outreach`, domain email, lead qualification, owner-reviewed drafts, durable scheduling, inbox, signed events and suppression. Client accounts cannot access its UI or APIs. GitHub Pages cannot execute this backend; deploy it on a persistent HTTPS host using the included Docker/Compose setup.

Read [outreach operations and DNS setup](outreach/OPERATIONS.md). Sending remains disabled until real credentials, domain verification and permitted use are configured. Run `python -m unittest outreach.tests -v` for security and queue tests.
