"""Mailgun adapter: sending, signed incoming messages and delivery events."""
import base64
import hashlib
import hmac
import json
import os
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from typing import Protocol
from outreach.core import Rejected, audit, email_address, now, suppress, transaction


class Retryable(Exception):
    pass


class Permanent(Exception):
    pass


class EmailProvider(Protocol):
    @property
    def ready(self) -> bool: ...
    def send(self, message: dict, lead: dict) -> str: ...


def unsubscribe_token(ident):
    secret = os.environ.get('UNSUBSCRIBE_SECRET', '')
    if len(secret) < 32:
        raise Permanent('UNSUBSCRIBE_SECRET is required.')
    return hmac.new(secret.encode(), str(ident).encode(), hashlib.sha256).hexdigest()


class Mailgun:
    @property
    def ready(self):
        return all(os.environ.get(k) for k in ('MAILGUN_API_KEY', 'MAILGUN_DOMAIN', 'MAILGUN_SIGNING_KEY', 'MAIL_FROM', 'PUBLIC_ORIGIN')) and len(os.environ.get('UNSUBSCRIBE_SECRET', '')) >= 32 and os.environ.get('EMAIL_ENABLED') == 'true' and os.environ.get('DOMAIN_VERIFIED') == 'true' and os.environ.get('PROVIDER_USE_APPROVED') == 'true'

    def send(self, message, lead):
        origin = os.environ['PUBLIC_ORIGIN'].rstrip('/')
        unsubscribe = origin + f"/unsubscribe/{message['id']}/{unsubscribe_token(message['id'])}"
        reply_address = os.environ.get('MAIL_REPLY_TO', os.environ['MAIL_FROM'])
        payload = {'from': 'Senthil — ForgeLaunch <' + os.environ['MAIL_FROM'] + '>', 'to': lead['email'],
                   'subject': message['subject'], 'text': message['body'] + '\n\nTo stop emails from ForgeLaunch: ' + unsubscribe,
                   'h:Reply-To': reply_address, 'h:List-Unsubscribe': '<' + unsubscribe + '>',
                   'h:List-Unsubscribe-Post': 'List-Unsubscribe=One-Click', 'v:outreach_id': str(message['id']),
                   'o:tracking': 'no'}
        if message['in_reply_to']:
            payload['h:In-Reply-To'] = message['in_reply_to']
            payload['h:References'] = message['in_reply_to']
        host = 'https://api.eu.mailgun.net' if os.environ.get('MAILGUN_REGION') == 'eu' else 'https://api.mailgun.net'
        domain = os.environ['MAILGUN_DOMAIN']
        if not all(c.isalnum() or c in '.-' for c in domain):
            raise Permanent('Invalid provider domain.')
        auth = base64.b64encode(('api:' + os.environ['MAILGUN_API_KEY']).encode()).decode()
        request = Request(host + '/v3/' + domain + '/messages', data=urlencode(payload).encode(), headers={'Authorization': 'Basic ' + auth})
        try:
            with urlopen(request, timeout=20) as response:
                data = json.load(response)
                if not data.get('id'):
                    raise RuntimeError('Provider acceptance unclear; reconcile before retrying.')
                return data['id']
        except HTTPError as exc:
            if exc.code == 429:
                raise Retryable('Provider rate limit; safely retry later.')
            if 400 <= exc.code < 500:
                raise Permanent('Provider rejected request: HTTP ' + str(exc.code))
            raise RuntimeError('Provider response ambiguous: HTTP ' + str(exc.code))


def verify_signature(signature):
    key = os.environ.get('MAILGUN_SIGNING_KEY', '')
    timestamp = str(signature.get('timestamp', ''))
    token = str(signature.get('token', ''))
    try:
        valid_time = abs(time.time() - int(timestamp)) <= 300
    except ValueError:
        valid_time = False
    if not key or not valid_time or not token or len(token) > 500:
        raise Rejected('Invalid webhook signature.', 401)
    expected = hmac.new(key.encode(), (timestamp + token).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(signature.get('signature', ''))):
        raise Rejected('Invalid webhook signature.', 401)


def remember_signature(db, signature, payload):
    fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    token = str(signature['token'])
    old = db.execute('SELECT fingerprint FROM webhook_tokens WHERE token=?', (token,)).fetchone()
    if old and old['fingerprint'] != fingerprint:
        raise Rejected('Webhook token replay with changed content.', 401)
    db.execute('INSERT OR IGNORE INTO webhook_tokens VALUES(?,?,?)', (token, fingerprint, now()))


def event(db, payload):
    verify_signature(payload.get('signature', {}))
    data = payload.get('event-data', {})
    ident = str(data.get('id', ''))
    kind = data.get('event')
    if not ident or len(ident) > 500 or kind not in ('accepted', 'delivered', 'failed', 'complained', 'unsubscribed'):
        raise Rejected('Unsupported provider event.')
    provider_id = data.get('message', {}).get('headers', {}).get('message-id')
    # Mailgun sends message-id with or without surrounding angle brackets.
    bare = str(provider_id or '').strip('<>')
    with transaction(db):
        remember_signature(db, payload['signature'], payload)
        if db.execute('SELECT 1 FROM events WHERE id=?', ('event:' + ident,)).fetchone():
            return {'duplicate': True}
        message = db.execute("SELECT * FROM messages WHERE provider_id IN (?,?)", (bare, '<' + bare + '>')).fetchone()
        if not message:
            candidate = data.get('user-variables', {}).get('outreach_id')
            message = db.execute("SELECT * FROM messages WHERE id=? AND state IN ('sending','uncertain','sent')", (candidate,)).fetchone()
        if not message:
            raise Rejected('Unknown message; retry after send transaction commits.', 503)
        lead = db.execute('SELECT * FROM leads WHERE id=?', (message['lead_id'],)).fetchone()
        if email_address(data.get('recipient', '')) != lead['email']:
            raise Rejected('Recipient mismatch.')
        db.execute('INSERT INTO events VALUES(?,?,?,?)', ('event:' + ident, kind, message['id'], now()))
        if kind in ('complained', 'unsubscribed') or (kind == 'failed' and data.get('severity') == 'permanent'):
            suppress(db, lead['email'], kind)
            db.execute("UPDATE messages SET state='bounced',error=? WHERE id=?", (kind, message['id']))
        elif kind in ('accepted', 'delivered') and message['state'] not in ('bounced', 'cancelled'):
            state = 'delivered' if kind == 'delivered' else ('delivered' if message['state'] == 'delivered' else 'sent')
            db.execute('UPDATE messages SET state=?,provider_id=COALESCE(provider_id,?),sent_at=COALESCE(sent_at,?),error=NULL WHERE id=?', (state, '<' + bare + '>' if bare else None, now(), message['id']))
        elif kind == 'failed':
            db.execute('UPDATE messages SET error=? WHERE id=?', ('Temporary delivery failure; provider manages redelivery.', message['id']))
        audit(db, 'mailgun', 'event.' + kind, message['id'])
    return {'ok': True}


def inbound(db, data):
    verify_signature(data)
    sender = email_address(data.get('sender', ''))
    expected = os.environ.get('MAIL_REPLY_TO', os.environ.get('MAIL_FROM', '')).lower()
    if not expected or str(data.get('recipient', '')).lower() != expected:
        raise Rejected('Inbound recipient not configured or does not match.')
    headers = data.get('message-headers', [])
    if isinstance(headers, str):
        try:
            headers = json.loads(headers)
        except ValueError:
            raise Rejected('Invalid inbound headers.')
    normalized = {str(key).lower(): str(value) for key, value in headers}
    ident = str(data.get('Message-Id') or data.get('message-id') or normalized.get('message-id', ''))
    if not ident or len(ident) > 500:
        raise Rejected('Inbound message identifier required.')
    subject = str(data.get('subject', ''))[:500]
    body = str(data.get('stripped-text') or data.get('body-plain') or '')[:50000]
    reference = str(data.get('In-Reply-To') or normalized.get('in-reply-to', ''))[:500]
    with transaction(db):
        remember_signature(db, data, data)
        if db.execute('SELECT 1 FROM inbox WHERE id=?', (ident,)).fetchone():
            return {'duplicate': True}
        lead = db.execute('SELECT * FROM leads WHERE email=?', (sender,)).fetchone()
        db.execute('INSERT INTO inbox VALUES(?,?,?,?,?,?,?)', (ident, lead['id'] if lead else None, sender, subject, body, reference, now()))
        if lead:
            db.execute("UPDATE leads SET state='replied' WHERE id=? AND state!='suppressed'", (lead['id'],))
            db.execute("UPDATE messages SET state='cancelled',error='Reply received; pending first contact stopped' WHERE lead_id=? AND kind='first' AND state IN ('approved','queued','retry')", (lead['id'],))
        audit(db, 'mailgun', 'reply.received', ident)
    return {'ok': True}
