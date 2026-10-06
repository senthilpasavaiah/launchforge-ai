"""WSGI application; serve with gunicorn behind HTTPS in production."""
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import secrets
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, unquote
from email.parser import BytesParser
from email.policy import default
from outreach import core
from outreach.provider import selected, event, inbound, unsubscribe_token

LOG = logging.getLogger('outreach')


def body(environ):
    length = int(environ.get('CONTENT_LENGTH') or 0)
    if length > 2_000_000:
        raise core.Rejected('Request too large.', 413)
    raw = environ['wsgi.input'].read(length)
    content_type = environ.get('CONTENT_TYPE', '')
    if content_type.startswith('application/json'):
        result = json.loads(raw or b'{}')
        if not isinstance(result, dict):
            raise core.Rejected('Expected a JSON object.')
        return result
    if content_type.startswith('multipart/form-data'):
        mail = BytesParser(policy=default).parsebytes(('Content-Type: ' + content_type + '\r\nMIME-Version: 1.0\r\n\r\n').encode() + raw)
        return {part.get_param('name', header='content-disposition'): part.get_content() for part in mail.iter_parts() if not part.get_filename()}
    if content_type.startswith('application/x-www-form-urlencoded'):
        return {k: v[0] for k, v in parse_qs(raw.decode()).items()}
    raise core.Rejected('Unsupported request format.', 415)


def actor(db, environ):
    auth = environ.get('HTTP_AUTHORIZATION', '')
    service = os.environ.get('AI_SERVICE_TOKEN', '')
    if auth.startswith('Bearer ') and len(service) >= 32 and hmac.compare_digest(auth[7:], service):
        return {'id': 'ai-service', 'name': 'Research worker', 'role': 'service'}, None
    cookie = SimpleCookie()
    cookie.load(environ.get('HTTP_COOKIE', ''))
    token = cookie.get('forge_session')
    if not token:
        return None, None
    digest = hashlib.sha256(token.value.encode()).hexdigest()
    session = db.execute('SELECT s.csrf,u.id,u.name,u.role,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?', (digest, core.now())).fetchone()
    return (dict(session), digest) if session else (None, None)


def application(environ, start_response):
    db = core.connect()
    headers = [('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'DENY'), ('Referrer-Policy', 'no-referrer')]
    status, payload, content_type = 200, {}, 'application/json; charset=utf-8'
    try:
        method = environ['REQUEST_METHOD']
        path = unquote(environ.get('PATH_INFO', '/'))
        user, session = actor(db, environ)
        is_local = os.environ.get('LOCAL_DEV') == 'true'
        origin = os.environ.get('PUBLIC_ORIGIN', '')
        if not is_local and not origin.startswith('https://'):
            raise core.Rejected('Production HTTPS origin must be configured.', 503)
        if method not in ('GET', 'POST', 'HEAD'):
            raise core.Rejected('Method not allowed.', 405)
        if path.startswith('/api/outreach'):
            core.require(user, 'write' if user and user['role'] == 'service' else 'read')
            if method == 'POST' and session:
                if environ.get('HTTP_ORIGIN') != origin or not hmac.compare_digest(environ.get('HTTP_X_CSRF_TOKEN', ''), user['csrf']):
                    raise core.Rejected('Request verification failed.', 403)
            payload = api(db, user, method, path, body(environ) if method == 'POST' else {})
            if path == '/api/outreach/gmail/connect' and method == 'POST':
                oauth_state = parse_qs(payload['authorization_url'].split('?',1)[1])['state'][0]
                headers.append(('Set-Cookie','forge_oauth='+oauth_state+'; HttpOnly; SameSite=Lax; Path=/auth/gmail/callback; Max-Age=600'+('' if is_local else '; Secure')))
        elif path == '/auth/gmail/callback' and method == 'GET':
            from outreach.gmail import callback
            query = {k:v[0] for k,v in parse_qs(environ.get('QUERY_STRING','')).items()}
            cookie = SimpleCookie();cookie.load(environ.get('HTTP_COOKIE',''))
            binding = cookie.get('forge_oauth')
            if not binding or not hmac.compare_digest(binding.value,query.get('state','')):
                raise core.Rejected('Google authorization does not belong to this browser.',403)
            state_hash = hashlib.sha256(binding.value.encode()).hexdigest()
            identity = db.execute('SELECT u.id,u.role,s.token FROM gmail_oauth_states g JOIN sessions s ON s.token=g.session JOIN users u ON u.id=s.user_id WHERE g.state=? AND g.expires>? AND s.expires>?',(state_hash,core.now(),core.now())).fetchone()
            if not identity:
                raise core.Rejected('Owner session expired. Sign in and reconnect Gmail.',403)
            callback(db,dict(identity),identity['token'],query)
            headers.append(('Set-Cookie','forge_oauth=; HttpOnly; SameSite=Lax; Path=/auth/gmail/callback; Max-Age=0'+('' if is_local else '; Secure')))
            # The normal Strict session cookie is available on the same-origin redirect.
            status,payload,content_type = 302,b'','text/html; charset=utf-8'
            headers.append(('Location','/admin/outreach'))
        elif path == '/auth/login' and method == 'POST':
            if environ.get('HTTP_ORIGIN') != origin:
                raise core.Rejected('Request origin mismatch.', 403)
            data = body(environ)
            ip = environ.get('REMOTE_ADDR', 'unknown')
            with core.transaction(db):
                attempt = db.execute('SELECT * FROM login_attempts WHERE ip=?', (ip,)).fetchone()
                if attempt and attempt['reset'] > core.now() and attempt['count'] >= 8:
                    raise core.Rejected('Too many attempts. Try again in 15 minutes.', 429)
                db.execute('INSERT INTO login_attempts VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET count=CASE WHEN reset<? THEN 1 ELSE count+1 END,reset=CASE WHEN reset<? THEN excluded.reset ELSE reset END', (ip, core.now()+900, core.now(), core.now()))
            account = db.execute('SELECT * FROM users WHERE email=?', (str(data.get('email', '')).lower(),)).fetchone()
            valid = core.check_password(str(data.get('password', '')), account['password'] if account else DUMMY_PASSWORD)
            if not account or not valid:
                raise core.Rejected('Invalid email or password.', 401)
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            with core.transaction(db):
                db.execute('DELETE FROM sessions WHERE expires<?', (core.now(),))
                db.execute('INSERT INTO sessions VALUES(?,?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), account['id'], csrf, core.now()+28800))
                db.execute('DELETE FROM login_attempts WHERE ip=?', (ip,))
                core.audit(db, account['id'], 'auth.login', account['id'])
            headers.append(('Set-Cookie', 'forge_session=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800' + ('' if is_local else '; Secure')))
            payload = {'role': account['role']}
        elif path == '/auth/logout' and method == 'POST':
            if not session or environ.get('HTTP_ORIGIN') != origin or environ.get('HTTP_X_CSRF_TOKEN') != user['csrf']:
                raise core.Rejected('Access denied.', 403)
            db.execute('DELETE FROM sessions WHERE token=?', (session,))
            headers.append(('Set-Cookie', 'forge_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' + ('' if is_local else '; Secure')))
            payload = {'ok': True}
        elif path == '/webhooks/mailgun/events' and method == 'POST':
            payload = event(db, body(environ))
        elif path == '/webhooks/mailgun/inbound' and method == 'POST':
            payload = inbound(db, body(environ))
        elif path.startswith('/unsubscribe/'):
            parts = path.split('/')
            if len(parts) != 4 or not hmac.compare_digest(parts[3], unsubscribe_token(parts[2])):
                raise core.Rejected('Invalid unsubscribe link.', 403)
            message = core.get_message(db, parts[2])
            if method == 'POST':
                with core.transaction(db):
                    lead = db.execute('SELECT email FROM leads WHERE id=?', (message['lead_id'],)).fetchone()
                    core.suppress(db, lead['email'], 'unsubscribed', 'recipient')
                payload = b'<h1>You are unsubscribed.</h1><p>ForgeLaunch will send no further outreach to this address.</p>'
            else:
                payload = b'<h1>Stop ForgeLaunch emails</h1><form method="post"><button>Unsubscribe</button></form>'
            content_type = 'text/html; charset=utf-8'
        elif path == '/health' and method in ('GET','HEAD'):
            payload = {'ok': True}
        elif method in ('GET','HEAD'):
            if path in ('/admin/outreach', '/admin/outreach/'):
                if not user:
                    status, payload = 302, b''
                    headers.append(('Location', '/admin/login'))
                else:
                    core.require(user, 'read')
                    payload = (core.ROOT / 'outreach' / 'ui' / 'admin.html').read_bytes()
                content_type = 'text/html; charset=utf-8'
                headers.append(('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"))
            elif path == '/admin/login':
                payload = (core.ROOT / 'outreach' / 'ui' / 'login.html').read_bytes()
                content_type = 'text/html; charset=utf-8'
            elif path in ('/admin/style.css', '/admin/admin.js', '/admin/login.js'):
                file = core.ROOT / 'outreach' / 'ui' / Path(path).name
                payload = file.read_bytes()
                content_type = mimetypes.guess_type(file)[0] or 'text/plain'
            else:
                # Explicit allowlist: never serve business/, private/, sources, DB or secrets.
                allowed = ('/', '/index.html', '/demo/', '/demo/index.html', '/case-study/', '/case-study/index.html', '/commodity-desk/', '/commodity-desk/index.html', '/commodity-desk/data.json')
                file = (core.ROOT / (path.lstrip('/') + ('index.html' if path.endswith('/') else ''))).resolve()
                assets = core.ROOT / 'assets'
                if path not in allowed and not (path.startswith('/assets/') and file.is_relative_to(assets) and file.suffix in ('.png','.svg','.webp')):
                    raise core.Rejected('Not found.', 404)
                if not file.is_file():
                    raise core.Rejected('Not found.', 404)
                payload = file.read_bytes()
                content_type = mimetypes.guess_type(file)[0] or 'application/octet-stream'
        else:
            raise core.Rejected('Not found.', 404)
    except core.Rejected as exc:
        status, payload = exc.status, {'error': str(exc)}
    except (ValueError, KeyError, TypeError) as exc:
        status, payload = 400, {'error': 'Invalid request.'}
    except Exception:
        LOG.exception('Request failed')
        status, payload = 500, {'error': 'Request failed; no changes confirmed.'}
    finally:
        db.close()
    if not isinstance(payload, bytes):
        payload = json.dumps(payload).encode()
    headers.extend([('Content-Type', content_type), ('Content-Length', str(len(payload)))])
    reasons = {200:'OK',302:'Found',400:'Bad Request',401:'Unauthorized',403:'Forbidden',404:'Not Found',405:'Method Not Allowed',409:'Conflict',413:'Payload Too Large',415:'Unsupported Media Type',429:'Too Many Requests',500:'Internal Server Error',503:'Service Unavailable'}
    start_response(str(status) + ' ' + reasons.get(status, 'Error'), headers)
    return [b'' if environ.get('REQUEST_METHOD') == 'HEAD' else payload]


def api(db, user, method, path, data):
    if method == 'GET':
        core.require(user, 'read')
        if path == '/api/outreach/me':
            return {k: user[k] for k in ('id','name','role','csrf')}
        if path == '/api/outreach/state':
            messages = [dict(r) for r in db.execute('SELECT * FROM messages ORDER BY id DESC LIMIT 500')]
            analytics = dict(db.execute('SELECT state,count(*) FROM messages GROUP BY state').fetchall())
            return {'leads':[dict(r) for r in db.execute('SELECT * FROM leads ORDER BY id DESC LIMIT 500')], 'messages':messages,
                    'inbox':[dict(r) for r in db.execute('SELECT * FROM inbox ORDER BY created DESC LIMIT 500')],
                    'suppression':[dict(r) for r in db.execute('SELECT * FROM suppression ORDER BY created DESC LIMIT 500')],
                    'audit':[dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')], 'analytics':analytics,
                    'provider_ready':selected(db).ready, 'paused':db.execute("SELECT value FROM settings WHERE key='paused'").fetchone()[0]=='1',
                    'provider':os.environ.get('EMAIL_PROVIDER','gmail'), 'gmail':gmail_status(db),
                    'sender':gmail_status(db)['email'] or os.environ.get('MAIL_FROM','Not connected'), 'schedule':'Saturday–Thursday, 09:00–17:00 Gulf (UTC+4); Friday paused; maximum 20/day.'}
        raise core.Rejected('Not found.', 404)
    if path == '/api/outreach/leads':
        return {'id':core.add_lead(db,user,data)}
    if path == '/api/outreach/drafts':
        return {'id':core.add_draft(db,user,data)}
    if path == '/api/outreach/gmail/connect':
        from outreach.gmail import authorize
        session = db.execute('SELECT token FROM sessions WHERE user_id=? AND csrf=? AND expires>?',(user['id'],user.get('csrf'),core.now())).fetchone()
        if not session:
            raise core.Rejected('A signed-in owner session is required.',403)
        return {'authorization_url':authorize(db,user,session['token'])}
    if path == '/api/outreach/gmail/disconnect':
        from outreach.gmail import disconnect
        return disconnect(db,user)
    if path == '/api/outreach/gmail/sync':
        core.require(user,'settings')
        from outreach.gmail import Gmail
        return Gmail(db).sync()
    if path == '/api/outreach/pause':
        core.require(user,'settings')
        with core.transaction(db):
            db.execute("UPDATE settings SET value=? WHERE key='paused'", ('1' if data.get('paused') else '0',))
            core.audit(db,user['id'],'queue.pause',bool(data.get('paused')))
        return {'ok':True}
    if path == '/api/outreach/suppress':
        core.require(user,'settings')
        with core.transaction(db):
            core.suppress(db,data.get('email',''),core.text(data,'reason',300),user['id'])
        return {'ok':True}
    parts = path.split('/')
    if len(parts)==6:
        ident, action = int(parts[4]), parts[5]
        if parts[3]=='leads' and action=='qualify':
            core.qualify(db,user,ident,data)
            return {'ok':True}
        if parts[3]=='leads' and action=='draft':
            return {'id':core.research_draft(db,user,ident)}
        if parts[3]=='messages' and action=='approve':
            core.approve(db,user,ident,data)
            return {'ok':True}
        if parts[3]=='messages' and action=='schedule':
            return {'scheduled':core.schedule(db,user,ident,data.get('timestamp',core.now()))}
        if parts[3]=='messages' and action=='cancel':
            core.require(user,'schedule')
            with core.transaction(db):
                message=core.get_message(db,ident)
                if message['state'] not in ('draft','approved','queued','retry'):
                    raise core.Rejected('This message cannot be cancelled.')
                db.execute("UPDATE messages SET state='cancelled' WHERE id=?",(ident,))
                core.audit(db,user['id'],'message.cancelled',ident)
            return {'ok':True}
    raise core.Rejected('Not found.',404)


def gmail_status(db):
    from outreach.gmail import configured
    connection = db.execute('SELECT email,status FROM gmail_connection WHERE id=1').fetchone()
    last = db.execute("SELECT value FROM settings WHERE key='gmail_last_sync'").fetchone()
    return {'configured':bool(configured()),'email':connection['email'] if connection else None,
            'status':connection['status'] if connection else 'not_connected','last_sync':int(last[0]) if last else None}


# Constant-time-ish failed login path without creating any user account.
DUMMY_PASSWORD = 'unusedsalt:' + hashlib.pbkdf2_hmac('sha256', b'not-a-login-password', b'unusedsalt', 600000).hex()
