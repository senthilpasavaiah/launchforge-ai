"""Direct Gmail OAuth/API integration; never uses ChatGPT connector credentials."""
import base64
import hashlib
import json
import os
import secrets
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.error import HTTPError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen
from outreach import core
from outreach.provider import Permanent, Retryable, unsubscribe_token

SCOPES = ('https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly')
API = 'https://gmail.googleapis.com/gmail/v1/users/me/'
TOKEN = 'https://oauth2.googleapis.com/token'


class AuthorizationUnavailable(Retryable):
    """Google explicitly rejected access before accepting any send."""
    authorization_unavailable = True


def configured():
    return all(os.environ.get(k) for k in ('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GMAIL_ALLOWED_EMAIL', 'PUBLIC_ORIGIN'))


def redirect_uri():
    return os.environ['PUBLIC_ORIGIN'].rstrip('/') + '/auth/gmail/callback'


def token_request(fields):
    try:
        request = Request(TOKEN, data=urlencode(fields).encode())
        with urlopen(request, timeout=20) as response:
            return json.load(response)
    except HTTPError as exc:
        if exc.code in (400, 401):
            raise core.Rejected('Google authorization expired or was revoked. Reconnect Gmail.', 503)
        raise core.Rejected('Google authorization is temporarily unavailable.', 503)


def authorize(db, owner, session):
    core.require(owner, 'settings')
    if not configured():
        raise core.Rejected('Google Cloud OAuth credentials must be configured before Google can show the permission screen.', 503)
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    with core.transaction(db):
        db.execute('DELETE FROM gmail_oauth_states WHERE expires<?', (core.now(),))
        db.execute('INSERT INTO gmail_oauth_states VALUES(?,?,?,?)', (hashlib.sha256(state.encode()).hexdigest(), session, verifier, core.now()+600))
    return 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode({
        'client_id':os.environ['GOOGLE_CLIENT_ID'], 'redirect_uri':redirect_uri(),
        'response_type':'code', 'scope':' '.join(SCOPES), 'access_type':'offline',
        'prompt':'consent', 'state':state, 'login_hint':os.environ['GMAIL_ALLOWED_EMAIL'],
        'code_challenge':challenge, 'code_challenge_method':'S256'})


def callback(db, owner, session, query):
    core.require(owner, 'settings')
    state = hashlib.sha256(str(query.get('state', '')).encode()).hexdigest()
    with core.transaction(db):
        record = db.execute('SELECT * FROM gmail_oauth_states WHERE state=? AND session=? AND expires>?', (state, session, core.now())).fetchone()
        if not record:
            raise core.Rejected('Google authorization request expired or does not belong to this owner session.', 403)
        db.execute('DELETE FROM gmail_oauth_states WHERE state=?', (state,))
    if query.get('error') or not query.get('code'):
        raise core.Rejected('Gmail permission was not granted. You can connect again from Email setup.')
    tokens = token_request({'code':query['code'], 'client_id':os.environ['GOOGLE_CLIENT_ID'], 'client_secret':os.environ['GOOGLE_CLIENT_SECRET'], 'redirect_uri':redirect_uri(), 'grant_type':'authorization_code', 'code_verifier':record['verifier']})
    if not set(SCOPES).issubset(set(str(tokens.get('scope', '')).split())):
        raise core.Rejected('Both send and read permissions are required; Gmail was not connected.')
    access = tokens.get('access_token')
    if not access:
        raise core.Rejected('Google returned no access token.')
    request = Request(API+'profile', headers={'Authorization':'Bearer '+access})
    with urlopen(request, timeout=20) as response:
        profile = json.load(response)
    mailbox = core.email_address(profile.get('emailAddress',''))
    if mailbox != core.email_address(os.environ['GMAIL_ALLOWED_EMAIL']):
        # Never attach a different mailbox just because the owner selected it in Google.
        raise core.Rejected('That Google account is not the configured ForgeLaunch Gmail address.', 403)
    existing = db.execute('SELECT * FROM gmail_connection WHERE id=1').fetchone()
    refresh = tokens.get('refresh_token') or (existing['refresh_token'] if existing and existing['email']==mailbox else '')
    if not refresh:
        raise core.Rejected('Offline access was not granted. Reconnect Gmail to keep scheduled work running.')
    with core.transaction(db):
        db.execute('INSERT OR REPLACE INTO gmail_connection VALUES(1,?,?,?,?,?)', (mailbox,refresh,access,core.now()+int(tokens.get('expires_in',3600)),'connected'))
        db.execute('INSERT OR IGNORE INTO settings VALUES(?,?)', ('gmail_instance',secrets.token_hex(16)))
        core.audit(db,owner['id'],'gmail.connected',mailbox)


def disconnect(db, owner):
    core.require(owner,'settings')
    record = db.execute('SELECT * FROM gmail_connection WHERE id=1').fetchone()
    with core.transaction(db):
        db.execute('DELETE FROM gmail_connection')
        db.execute('DELETE FROM gmail_oauth_states')
        core.audit(db,owner['id'],'gmail.disconnected','owner request')
    if record:
        try:
            with urlopen(Request('https://oauth2.googleapis.com/revoke',data=urlencode({'token':record['refresh_token']}).encode()),timeout=20):
                pass
        except Exception:
            # Local access is removed even if Google's revocation endpoint is unavailable.
            return {'ok':True,'notice':'Local connection removed. Also remove ForgeLaunch access in your Google account to ensure remote revocation.'}
    return {'ok':True}


class Gmail:
    def __init__(self, db):
        self.db = db

    @property
    def ready(self):
        connection = self.db.execute("SELECT 1 FROM gmail_connection WHERE id=1 AND status='connected'").fetchone()
        return bool(configured() and connection and os.environ.get('EMAIL_ENABLED')=='true' and len(os.environ.get('UNSUBSCRIBE_SECRET',''))>=32)

    def access(self):
        connection = self.db.execute('SELECT * FROM gmail_connection WHERE id=1').fetchone()
        if not connection or connection['status']!='connected':
            raise Permanent('Gmail is not connected. Owner authorization required.')
        if connection['expires']>core.now()+60:
            return connection['access_token']
        try:
            tokens=token_request({'client_id':os.environ['GOOGLE_CLIENT_ID'],'client_secret':os.environ['GOOGLE_CLIENT_SECRET'],'refresh_token':connection['refresh_token'],'grant_type':'refresh_token'})
        except core.Rejected as exc:
            # Persist status outside the send transaction with prepare() in the worker.
            if 'revoked' in str(exc):
                self.db.execute("UPDATE gmail_connection SET status='reconnect_required' WHERE id=1")
            raise
        if not tokens.get('access_token'):
            raise core.Rejected('Google access refresh failed.',503)
        self.db.execute('UPDATE gmail_connection SET access_token=?,expires=? WHERE id=1',(tokens['access_token'],core.now()+int(tokens.get('expires_in',3600))))
        return tokens['access_token']

    def prepare(self):
        # Refresh before claiming messages. An authorization outage keeps their queue intact.
        self.access()

    def request(self,path,data=None):
        raw=json.dumps(data).encode() if data is not None else None
        request=Request(API+path,data=raw,headers={'Authorization':'Bearer '+self.access(),'Content-Type':'application/json'})
        try:
            with urlopen(request,timeout=20) as response:return json.load(response)
        except HTTPError as exc:
            if exc.code==401:
                raise AuthorizationUnavailable('Gmail permission is invalid; reconnect before resuming.')
            if exc.code==429:
                raise Retryable('Gmail rate limit; retry later.')
            if exc.code==403:
                # Google rejects quota/permission errors before accepting this request.
                raise Retryable('Gmail quota or access restriction; owner should review Google setup.')
            if 400<=exc.code<500:
                raise Permanent('Gmail rejected request: HTTP '+str(exc.code))
            raise RuntimeError('Gmail response ambiguous; reconcile before sending again.')

    def rfc_id(self,ident):
        instance=self.db.execute("SELECT value FROM settings WHERE key='gmail_instance'").fetchone()
        if not instance:raise Permanent('Reconnect Gmail to initialize message identifiers.')
        return f"<forge-{instance[0]}-{ident}@gmail.com>"

    def send(self,message,lead):
        mailbox=self.db.execute('SELECT email FROM gmail_connection WHERE id=1').fetchone()[0]
        mail=EmailMessage(policy=policy.SMTP)
        mail['From']='Senthil — ForgeLaunch <'+mailbox+'>'
        mail['To']=lead['email']
        mail['Subject']=message['subject']
        mail['Message-ID']=self.rfc_id(message['id'])
        link=os.environ['PUBLIC_ORIGIN'].rstrip('/')+f"/unsubscribe/{message['id']}/{unsubscribe_token(message['id'])}"
        mail['List-Unsubscribe']='<'+link+'>'
        mail['List-Unsubscribe-Post']='List-Unsubscribe=One-Click'
        mail.set_content(message['body']+'\n\nTo stop emails from ForgeLaunch: '+link)
        payload={}
        if message['in_reply_to']:
            mail['In-Reply-To']=message['in_reply_to'];mail['References']=message['in_reply_to']
            thread=self.db.execute('SELECT value FROM settings WHERE key=?',('gmail_reply_thread:'+message['in_reply_to'],)).fetchone()
            if thread:payload['threadId']=thread[0]
        payload['raw']=base64.urlsafe_b64encode(mail.as_bytes()).decode()
        result=self.request('messages/send',payload)
        if not result.get('id') or not result.get('threadId'):
            raise RuntimeError('Gmail acceptance unclear; reconcile before retrying.')
        self.db.execute('INSERT OR IGNORE INTO gmail_threads VALUES(?,?)',(result['threadId'],message['id']))
        self.db.execute('INSERT OR IGNORE INTO gmail_seen VALUES(?,?)',(result['id'],core.now()))
        return 'gmail:'+result['id']

    def raw(self,ident):
        data=self.request('messages/'+quote(ident,safe='')+'?format=raw')
        raw=str(data.get('raw',''))
        return BytesParser(policy=policy.default).parsebytes(base64.urlsafe_b64decode(raw+'='*((-len(raw))%4)))

    def receive(self,ident,thread,mail):
        if self.db.execute('SELECT 1 FROM gmail_seen WHERE id=?',(ident,)).fetchone():return
        sender=parseaddr(str(mail.get('From','')))[1].lower()
        rfc_id=str(mail.get('Message-ID','')).strip()
        if not rfc_id or len(rfc_id)>500:return
        connection=self.db.execute('SELECT email FROM gmail_connection WHERE id=1').fetchone()
        if not connection or sender==connection['email']:return
        lead=self.db.execute('SELECT * FROM leads WHERE email=?',(sender,)).fetchone()
        if not lead:return
        # Only accept a reply in a thread belonging to this same prospect.
        matching=self.db.execute('SELECT 1 FROM gmail_threads t JOIN messages m ON m.id=t.message_id WHERE t.id=? AND m.lead_id=?',(thread,lead['id'])).fetchone()
        if not matching:return
        part=mail.get_body(preferencelist=('plain',))
        body=part.get_content() if part else '[Plain-text content unavailable; open this message in Gmail.]'
        with core.transaction(self.db):
            self.db.execute('INSERT OR IGNORE INTO inbox VALUES(?,?,?,?,?,?,?)',(rfc_id,lead['id'],sender,str(mail.get('Subject',''))[:500],str(body)[:50000],str(mail.get('In-Reply-To',''))[:500],core.now()))
            self.db.execute('INSERT OR IGNORE INTO settings VALUES(?,?)',('gmail_reply_thread:'+rfc_id,thread))
            self.db.execute("UPDATE leads SET state='replied' WHERE id=? AND state!='suppressed'",(lead['id'],))
            self.db.execute("UPDATE messages SET state='cancelled',error='Gmail reply received' WHERE lead_id=? AND kind='first' AND state IN ('approved','queued','retry')",(lead['id'],))
            self.db.execute('INSERT OR IGNORE INTO gmail_seen VALUES(?,?)',(ident,core.now()))
            core.audit(self.db,'gmail','reply.received',rfc_id)

    def bounce(self,ident,mail):
        if self.db.execute('SELECT 1 FROM gmail_seen WHERE id=?',(ident,)).fetchone():return
        if mail.get_content_type()!='multipart/report' or mail.get_param('report-type')!='delivery-status':return
        refs=set()
        failures=[]
        for part in mail.walk():
            if part.get_content_type()=='message/delivery-status':
                for block in part.get_payload():
                    if block.get('Original-Message-ID'):refs.add(str(block['Original-Message-ID']).strip())
                    if str(block.get('Action','')).lower()=='failed' and str(block.get('Status','')).startswith('5.'):
                        recipient=str(block.get('Final-Recipient','')).split(';')[-1].strip().lower()
                        failures.append(recipient)
            if part.get_content_type()=='message/rfc822':
                for original in part.get_payload():
                    if original.get('Message-ID'):refs.add(str(original['Message-ID']).strip())
        if not refs or not failures:return
        messages=self.db.execute("SELECT m.*,l.email FROM messages m JOIN leads l ON l.id=m.lead_id WHERE m.state IN ('sent','uncertain')").fetchall()
        for message in messages:
            if self.rfc_id(message['id']) not in refs or message['email'] not in failures:continue
            with core.transaction(self.db):
                core.suppress(self.db,message['email'],'Gmail permanent delivery failure','gmail')
                self.db.execute("UPDATE messages SET state='bounced',error='Permanent delivery failure reported by email' WHERE id=?",(message['id'],))
                self.db.execute('INSERT OR IGNORE INTO gmail_seen VALUES(?,?)',(ident,core.now()))
            return

    def sync(self):
        connection=self.db.execute("SELECT 1 FROM gmail_connection WHERE status='connected'").fetchone()
        if not configured() or not connection:return {'blocked':'Gmail not connected.'}
        self.prepare()
        # Reconcile unknown send acceptance using the stable MIME Message-ID.
        for message in self.db.execute("SELECT id FROM messages WHERE state='uncertain' ORDER BY id LIMIT 20").fetchall():
            found=self.request('messages?'+urlencode({'q':'in:sent rfc822msgid:'+self.rfc_id(message['id']),'maxResults':2}))
            if len(found.get('messages',[]))==1:
                sent=found['messages'][0]
                with core.transaction(self.db):
                    self.db.execute("UPDATE messages SET state='sent',provider_id=?,sent_at=COALESCE(sent_at,?),error=NULL WHERE id=?",('gmail:'+sent['id'],core.now(),message['id']))
                    self.db.execute('INSERT OR IGNORE INTO gmail_threads VALUES(?,?)',(sent['threadId'],message['id']))
                    self.db.execute('INSERT OR IGNORE INTO gmail_seen VALUES(?,?)',(sent['id'],core.now()))
                    core.audit(self.db,'gmail','send.reconciled',message['id'])
        # Fair pagination through tracked threads; retry a failed batch without moving cursor.
        cursor=self.db.execute("SELECT value FROM settings WHERE key='gmail_thread_cursor'").fetchone()
        last=cursor[0] if cursor else ''
        threads=self.db.execute('SELECT id FROM gmail_threads WHERE id>? ORDER BY id LIMIT 50',(last,)).fetchall()
        if not threads:threads=self.db.execute('SELECT id FROM gmail_threads ORDER BY id LIMIT 50').fetchall()
        for row in threads:
            try:
                thread=self.request('threads/'+quote(row['id'],safe='')+'?format=minimal')
                for item in thread.get('messages',[]):
                    if not self.db.execute('SELECT 1 FROM gmail_seen WHERE id=?',(item['id'],)).fetchone():
                        mail=self.raw(item['id']);self.bounce(item['id'],mail);self.receive(item['id'],row['id'],mail)
            except Permanent:
                # Deleted/nonexistent Gmail threads do not prevent other threads from syncing.
                continue
        self.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',('gmail_thread_cursor',threads[-1]['id'] if threads else ''))
        # DSNs can arrive as a new thread. Read candidates without importing unrelated inbox mail.
        page=self.db.execute("SELECT value FROM settings WHERE key='gmail_bounce_page'").fetchone()
        query={'q':'in:anywhere newer_than:30d (from:mailer-daemon OR from:postmaster)','maxResults':50}
        if page and page[0]:query['pageToken']=page[0]
        data=self.request('messages?'+urlencode(query))
        for item in data.get('messages',[]):self.bounce(item['id'],self.raw(item['id']))
        self.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',('gmail_bounce_page',data.get('nextPageToken','')))
        self.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',('gmail_last_sync',str(core.now())))
        return {'ok':True,'threads_checked':len(threads)}
