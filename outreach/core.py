"""Durable domain logic. Public website files never contain private records."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GULF = timezone(timedelta(hours=4))


class Rejected(Exception):
    def __init__(self, message, status=400):
        self.status = status
        super().__init__(message)


def now():
    return int(time.time())


def connect(path=None):
    path = path or os.environ.get('OUTREACH_DB', str(ROOT / 'private' / 'outreach.sqlite'))
    if path != ':memory:':
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=30, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=30000')
    db.executescript((ROOT / 'outreach' / 'schema.sql').read_text())
    return db


@contextmanager
def transaction(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield
        db.execute('COMMIT')
    except Exception:
        db.execute('ROLLBACK')
        raise


def audit(db, actor, action, entity):
    db.execute('INSERT INTO audit(actor,action,entity,created) VALUES(?,?,?,?)',
               (str(actor), action, str(entity), now()))


def password_hash(password, salt=None):
    if len(password) < 16:
        raise Rejected('Use a password of at least 16 characters.')
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600000).hex()
    return salt + ':' + digest


def check_password(password, stored):
    salt, digest = stored.split(':')
    candidate = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600000).hex()
    return hmac.compare_digest(candidate, digest)


def email_address(value):
    value = str(value).strip().lower()
    if len(value) > 254 or not re.fullmatch(r'[a-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}', value):
        raise Rejected('A valid business email is required.')
    return value


def text(data, key, maximum=2000, required=True):
    value = str(data.get(key, '')).strip()
    if (required and not value) or len(value) > maximum:
        raise Rejected(f'{key} is required and must be at most {maximum} characters.')
    return value


def url(value):
    if not re.fullmatch(r'https?://[^\s]+', value):
        raise Rejected('Use an http or https evidence URL.')
    return value


def require(actor, action):
    permissions = {'owner': {'read', 'write', 'qualify', 'approve', 'schedule', 'settings'},
                   'admin': {'read', 'write', 'qualify'},
                   'service': {'write'}, 'client': set()}
    if not actor or action not in permissions.get(actor['role'], set()):
        raise Rejected('Access denied.', 403)


def digest(message):
    content = [message[k] for k in ('subject', 'body', 'kind', 'binding', 'in_reply_to')]
    return hashlib.sha256(json.dumps(content).encode()).hexdigest()


def window(timestamp):
    dt = datetime.fromtimestamp(timestamp, GULF)
    return dt.weekday() != 4 and 9 <= dt.hour < 17


def next_window(timestamp):
    dt = datetime.fromtimestamp(timestamp, GULF)
    if dt.hour >= 17:
        dt = (dt + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
    elif dt.hour < 9:
        dt = dt.replace(hour=9, minute=0, second=0, microsecond=0)
    if dt.weekday() == 4:
        dt = (dt + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
    return int(dt.timestamp())


def get_message(db, ident):
    row = db.execute('SELECT * FROM messages WHERE id=?', (ident,)).fetchone()
    if not row:
        raise Rejected('Message not found.', 404)
    return dict(row)


def add_lead(db, actor, data):
    require(actor, 'write')
    company = text(data, 'company', 200)
    email = email_address(data.get('email', ''))
    name = text(data, 'name', 200)
    country = text(data, 'country', 100)
    website = url(text(data, 'website', 1000))
    with transaction(db):
        if db.execute('SELECT 1 FROM suppression WHERE email=?', (email,)).fetchone():
            raise Rejected('This address is suppressed.')
        try:
            ident = db.execute('INSERT INTO leads(company,email,name,country,website,created) VALUES(?,?,?,?,?,?)',
                               (company, email, name, country, website, now())).lastrowid
        except sqlite3.IntegrityError:
            raise Rejected('This lead already exists.', 409)
        audit(db, actor['id'], 'lead.created', ident)
    return ident


def qualify(db, actor, ident, data):
    require(actor, 'qualify')
    observation = text(data, 'observation')
    evidence = url(text(data, 'evidence_url', 1000))
    consent = text(data, 'consent')
    if data.get('verified') is not True:
        raise Rejected('Confirm verification of this business email.')
    with transaction(db):
        lead = db.execute('SELECT * FROM leads WHERE id=?', (ident,)).fetchone()
        if not lead:
            raise Rejected('Lead not found.', 404)
        if db.execute('SELECT 1 FROM suppression WHERE email=?', (lead['email'],)).fetchone():
            raise Rejected('This lead is suppressed.')
        db.execute("UPDATE leads SET observation=?,evidence_url=?,consent=?,verified=1,state='qualified' WHERE id=?",
                   (observation, evidence, consent, ident))
        audit(db, actor['id'], 'lead.qualified', ident)


def add_draft(db, actor, data):
    require(actor, 'write')
    lead = db.execute('SELECT * FROM leads WHERE id=?', (data.get('lead_id'),)).fetchone()
    if not lead:
        raise Rejected('Lead not found.', 404)
    kind = data.get('kind', 'first')
    if kind not in ('first', 'reply'):
        raise Rejected('Only first contacts and replies are supported. No automated follow-ups.')
    subject = text(data, 'subject', 200)
    body = text(data, 'body', 5000)
    if '\r' in subject or '\n' in subject:
        raise Rejected('Subject must be one line.')
    if kind == 'first' and len(body.split()) > 180:
        raise Rejected('Keep first contact under 180 words.')
    reply_to = data.get('in_reply_to') or None
    if reply_to and (len(reply_to) > 500 or '\n' in reply_to or '\r' in reply_to):
        raise Rejected('Invalid reply reference.')
    if kind == 'reply' and not db.execute('SELECT 1 FROM inbox WHERE lead_id=? AND id=?', (lead['id'], reply_to)).fetchone():
        raise Rejected('Replies must reference a received message from this lead.')
    # Human review is mandatory for ALL messages, including paraphrased commercial terms.
    binding = bool(data.get('binding')) or bool(re.search(r'(?i)(price|pricing|scope|deliver|contract|refund|payment|\$|USD|AED|SAR|OMR|guarantee)', subject + body))
    with transaction(db):
        ident = db.execute('INSERT INTO messages(lead_id,subject,body,kind,binding,created,in_reply_to) VALUES(?,?,?,?,?,?,?)',
                           (lead['id'], subject, body, kind, int(binding), now(), reply_to)).lastrowid
        audit(db, actor['id'], 'draft.created', ident)
    return ident


def research_draft(db, actor, ident):
    require(actor, 'write')
    lead = db.execute('SELECT * FROM leads WHERE id=?', (ident,)).fetchone()
    if not lead or lead['state'] != 'qualified':
        raise Rejected('Qualify the lead with source evidence first.')
    body = (f"Hi {lead['name']},\n\nI noticed {lead['observation']}\n\n"
            "I run ForgeLaunch.ai. We build business applications, MVPs and workflow automations. "
            "Is this a workflow you are currently looking to improve? I can share a relevant approach if helpful.\n\n"
            "Regards,\nSenthil\nForgeLaunch.ai")
    return add_draft(db, actor, {'lead_id': ident, 'subject': f"Quick idea for {lead['company']}", 'body': body})


def safe(db, message):
    lead = db.execute('SELECT * FROM leads WHERE id=?', (message['lead_id'],)).fetchone()
    if db.execute('SELECT 1 FROM suppression WHERE email=?', (lead['email'],)).fetchone():
        raise Rejected('Address suppressed.')
    if not lead['verified'] or not lead['consent'] or not lead['observation'] or not lead['evidence_url']:
        raise Rejected('Verified contact, source research and consent evidence are required.')
    if not message['approved_by'] or message['approved_hash'] != digest(message):
        raise Rejected('Senthil must approve the exact message content.')
    owner = db.execute("SELECT 1 FROM users WHERE id=? AND role='owner'", (message['approved_by'],)).fetchone()
    if not owner:
        raise Rejected('Approval must come from the owner account.')
    if message['kind'] == 'first':
        if db.execute("SELECT 1 FROM inbox WHERE lead_id=?", (lead['id'],)).fetchone():
            raise Rejected('This lead has replied; use a reply draft.')
        if db.execute("SELECT 1 FROM messages WHERE lead_id=? AND kind='first' AND id!=? AND state NOT IN ('draft','cancelled')",
                      (lead['id'], message['id'])).fetchone():
            raise Rejected('First contact already queued or sent.', 409)
    return dict(lead)


def approve(db, actor, ident, data):
    require(actor, 'approve')
    if data.get('reviewed') is not True or data.get('terms_approved') is not True:
        raise Rejected('Confirm source accuracy and approval of any commercial terms.')
    with transaction(db):
        message = get_message(db, ident)
        if message['state'] != 'draft':
            raise Rejected('Only drafts can be approved.')
        message['approved_by'] = actor['id']
        message['approved_hash'] = digest(message)
        safe(db, message)
        db.execute("UPDATE messages SET state='approved',approved_by=?,approved_hash=? WHERE id=?",
                   (actor['id'], message['approved_hash'], ident))
        audit(db, actor['id'], 'message.approved', ident)


def schedule(db, actor, ident, timestamp):
    require(actor, 'schedule')
    timestamp = next_window(max(now(), int(timestamp)))
    with transaction(db):
        message = get_message(db, ident)
        if message['state'] != 'approved':
            raise Rejected('Approve this message before scheduling.')
        safe(db, message)
        db.execute("UPDATE messages SET state='queued',scheduled=?,retry_at=? WHERE id=?", (timestamp, timestamp, ident))
        audit(db, actor['id'], 'message.queued', ident)
    return timestamp


def suppress(db, email, reason, actor='provider'):
    email = email_address(email)
    db.execute('INSERT OR IGNORE INTO suppression VALUES(?,?,?)', (email, reason, now()))
    db.execute("UPDATE messages SET state='cancelled',error=? WHERE lead_id IN (SELECT id FROM leads WHERE email=?) AND state IN ('draft','approved','queued','retry')", (reason, email))
    db.execute("UPDATE leads SET state='suppressed' WHERE email=?", (email,))
    audit(db, actor, 'address.suppressed', email)


def worker(db, provider, timestamp=None):
    timestamp = now() if timestamp is None else timestamp
    counts = {'sent': 0, 'retry': 0, 'failed': 0, 'uncertain': 0}
    # Never re-send a crashed/expired in-flight request: external acceptance is unknown.
    with transaction(db):
        db.execute("UPDATE messages SET state='uncertain',error='Worker interrupted; reconcile provider before retrying' WHERE state='sending' AND lease_until<?", (timestamp,))
    if not window(timestamp) or db.execute("SELECT value FROM settings WHERE key='paused'").fetchone()[0] == '1':
        return counts
    if not provider.ready:
        return dict(counts, blocked='Provider configuration incomplete; queue preserved.')
    candidates = db.execute("SELECT id FROM messages WHERE state IN ('queued','retry') AND retry_at<=? ORDER BY retry_at,id LIMIT 20", (timestamp,)).fetchall()
    for row in candidates:
        with transaction(db):
            message = get_message(db, row['id'])
            if message['state'] not in ('queued', 'retry'):
                continue
            start = int(datetime.fromtimestamp(timestamp, GULF).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
            if db.execute("SELECT count(*) FROM worker_attempts WHERE created>=?", (start,)).fetchone()[0] >= 20:
                break
            try:
                lead = safe(db, message)
            except Rejected as exc:
                db.execute("UPDATE messages SET state='failed',error=? WHERE id=?", (str(exc), message['id']))
                counts['failed'] += 1
                continue
            db.execute("UPDATE messages SET state='sending',attempts=attempts+1,lease_until=? WHERE id=?", (timestamp + 120, message['id']))
            db.execute('INSERT INTO worker_attempts(message_id,created) VALUES(?,?)', (message['id'], timestamp))
        try:
            # A DB write lock makes suppression and send checks serialize across workers.
            with transaction(db):
                message = get_message(db, row['id'])
                lead = safe(db, message)
                provider_id = provider.send(message, lead)
                db.execute("UPDATE messages SET state='sent',provider_id=?,sent_at=?,error=NULL WHERE id=?", (provider_id, timestamp, message['id']))
                db.execute("UPDATE leads SET state='contacted' WHERE id=? AND state!='replied'", (lead['id'],))
                audit(db, 'worker', 'message.sent', message['id'])
            counts['sent'] += 1
        except Exception as exc:
            # Retry only explicit non-acceptance; timeouts/5xx may have sent the email.
            from outreach.provider import Retryable, Permanent
            with transaction(db):
                message = get_message(db, row['id'])
                if isinstance(exc, Retryable) and message['attempts'] < 5:
                    state = 'retry'
                    due = next_window(timestamp + min(3600, 60 * 2 ** message['attempts']))
                elif isinstance(exc, (Permanent, Rejected)) or isinstance(exc, Retryable):
                    state, due = 'failed', None
                else:
                    state, due = 'uncertain', None
                db.execute('UPDATE messages SET state=?,retry_at=?,error=? WHERE id=?', (state, due, str(exc)[:300], message['id']))
                audit(db, 'worker', 'message.' + state, message['id'])
                counts[state] += 1
    return counts
