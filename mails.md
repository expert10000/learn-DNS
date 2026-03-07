# Mail Lab Notes (IMAP, SWAKS, Inbox, DKIM)

> Note: "swat" in earlier notes likely refers to **SWAKS** (SMTP test tool). This file documents SWAKS.

## Overview
This project includes a self‑contained mail lab used to:
- Create test mailboxes.
- Send messages via SMTP (SWAKS).
- Inspect delivery and DKIM behavior via logs.
- Browse inbox messages over IMAP.

Key services/containers (see `docker-compose.yml`):
- Mail server: `dns_mailserver`
- SMTP test client: `dns_swaks`

## IMAP + Inbox (Viewer)
The UI provides an Inbox panel that lists messages and lets you preview a selected message.

### How it works (lab API)
- `POST /email/inbox/list`
  - Returns structured message headers for a mailbox.
  - Uses `doveadm fetch` when available.
  - Falls back to Maildir parsing in `/var/mail/<domain>/<user>` if `doveadm` fails.

- `POST /email/inbox/view`
  - Loads the message body for the selected message.
  - Uses `doveadm fetch` by UID when possible.
  - Falls back to reading the Maildir file directly.

- `POST /email/imap-check`
  - Older/raw header dump view. Useful for debugging.

### UI location
- Section: **Mail Delivery Lab → Inbox (IMAP)**
- Actions:
  - **List Messages**: refresh list
  - Click a message: loads viewer
  - **View Selected**: explicit reload for the selected message

## SWAKS (SMTP Test Sender)
SWAKS is used to send test emails without needing a full client. In this lab:

- `POST /email/send`
  - Runs SWAKS inside `dns_swaks`.
  - Supports TLS and SMTP auth parameters.

This is the fastest way to inject test messages into the mail server for DKIM/SPF verification and inbox checks.

## DKIM (Mail Signing)
DKIM adds a cryptographic signature to outbound messages to prove they were sent by an authorized domain and not modified in transit.

In this lab:
- DKIM results appear in mail logs (see next section).
- Use **Outbox / Logs** to confirm DKIM pass/fail and troubleshoot delivery.

## Logs / Outbox
- `GET /email/logs`
  - Tails the current mail log file in the mail server container.
  - Optional grep filter to narrow results (e.g., `dkim`, `postfix`).

UI location:
- Section: **Mail Delivery Lab → Outbox / Logs**

## Typical Flow
1. Create a mailbox (Mail Delivery Lab → Mailbox setup).
2. Send a test message (Compose & Send).
3. List messages in Inbox (IMAP).
4. Check DKIM status in logs (Outbox / Logs).

## Troubleshooting
- If IMAP list is empty:
  - Confirm the mailbox exists and a message was sent to it.
  - Check logs for delivery/queue errors.
- If IMAP list fails:
  - The API will fall back to Maildir parsing; check for messages in `/var/mail/<domain>/<user>` inside the mail server container.
- If DKIM fails:
  - Inspect the DKIM-related log entries and verify DNS records.

## Related Files
- UI: `react-ui/src/App.tsx`, `react-ui/src/index.css`
- API: `lab_api/app/main.py`
- Mail server config: `mailserver.env`, `docker-compose.yml`
