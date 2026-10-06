import hashlib
import hmac
import io
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch
from outreach import core
from outreach.app import application
from outreach.provider import event, inbound, Mailgun, Retryable, Permanent

MONDAY=int(datetime(2026,10,5,10,tzinfo=core.GULF).timestamp())


class FakeProvider:
    ready=True
    def __init__(self,errors=None):
        self.errors=errors or {}
        self.calls=[]
    def send(self,message,lead):
        self.calls.append(message['id'])
        if message['id'] in self.errors:
            raise self.errors[message['id']]
        return '<sent-'+str(message['id'])+'@mailgun.test>'


class OutreachTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pwhash=core.password_hash('A-long-local-test-password')

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=os.path.join(self.temp.name,'test.sqlite')
        self.env=patch.dict(os.environ,{'OUTREACH_DB':self.path,'LOCAL_DEV':'true','PUBLIC_ORIGIN':'http://127.0.0.1:8080','MAILGUN_SIGNING_KEY':'test-signing-key','MAIL_FROM':'sales@forgelaunch.test','MAIL_REPLY_TO':'reply@inbox.forgelaunch.test','UNSUBSCRIBE_SECRET':'x'*40,'AI_SERVICE_TOKEN':'s'*40,'EMAIL_ENABLED':'false'})
        self.env.start()
        self.db=core.connect()
        for email,name,role in [('senthil@test.example','Senthil','owner'),('admin@test.example','Admin','admin'),('client@test.example','Client','client')]:
            self.db.execute('INSERT INTO users(email,name,role,password) VALUES(?,?,?,?)',(email,name,role,self.pwhash))
        self.owner={'id':1,'role':'owner'}
        self.admin={'id':2,'role':'admin'}
        self.client={'id':3,'role':'client'}
        self.service={'id':'ai-service','role':'service'}

    def tearDown(self):
        self.db.close()
        self.env.stop()
        self.temp.cleanup()

    def lead(self,index=0):
        ident=core.add_lead(self.db,self.owner,{'company':f'Company {index}','email':f'person{index}@company.example','name':'Contact','country':'UAE','website':'https://company.example'})
        core.qualify(self.db,self.owner,ident,{'observation':'your new business portal announcement. Is workflow automation a priority?','evidence_url':'https://company.example/news','consent':'Contact requested a business workflow discussion on 2026-10-01.','verified':True})
        return ident

    def message(self,index=0):
        ident=core.research_draft(self.db,self.owner,self.lead(index))
        core.approve(self.db,self.owner,ident,{'reviewed':True,'terms_approved':True})
        with patch('outreach.core.now',return_value=MONDAY):
            core.schedule(self.db,self.owner,ident,MONDAY)
        return ident

    def call(self,path,method='GET',data=None,cookie='',csrf='',authorization=''):
        raw=json.dumps(data or {}).encode()
        environ={'PATH_INFO':path,'REQUEST_METHOD':method,'CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/json','wsgi.input':io.BytesIO(raw),'REMOTE_ADDR':'test-ip','HTTP_ORIGIN':'http://127.0.0.1:8080','HTTP_COOKIE':cookie,'HTTP_X_CSRF_TOKEN':csrf,'HTTP_AUTHORIZATION':authorization}
        captured={}
        def start(status,headers):
            captured['status']=int(status.split()[0]);captured['headers']=dict(headers)
        captured['body']=b''.join(application(environ,start))
        return captured

    def login(self,email):
        result=self.call('/auth/login','POST',{'email':email,'password':'A-long-local-test-password'})
        self.assertEqual(result['status'],200)
        return result['headers']['Set-Cookie'].split(';')[0]

    def signature(self,token='random-token'):
        timestamp=str(core.now())
        return {'timestamp':timestamp,'token':token,'signature':hmac.new(b'test-signing-key',(timestamp+token).encode(),hashlib.sha256).hexdigest()}

    def payload(self,ident,kind='delivered'):
        return {'signature':self.signature('token-'+str(ident)+'-'+kind),'event-data':{'id':'event-'+str(ident)+'-'+kind,'event':kind,'recipient':'person0@company.example','message':{'headers':{'message-id':'sent-'+str(ident)+'@mailgun.test'}},'severity':'permanent'}}

    def test_clients_and_anonymous_cannot_access_data(self):
        self.lead()
        self.assertEqual(self.call('/api/outreach/state')['status'],403)
        cookie=self.login('client@test.example')
        for path in ['/admin/outreach','/api/outreach/state','/api/outreach/me']:
            self.assertEqual(self.call(path,cookie=cookie)['status'],403)
        self.assertEqual(self.call('/api/outreach/leads','POST',{},cookie=cookie)['status'],403)

    def test_public_files_are_allowlisted(self):
        for path in ['/private/outreach.sqlite','/business/prospect-tracker.csv','/outreach/core.py','/.env','/assets/../outreach/app.py']:
            self.assertEqual(self.call(path)['status'],404)
        self.assertEqual(self.call('/')['status'],200)
        self.assertEqual(self.call('/admin/outreach')['status'],302)

    def test_admin_can_research_but_not_approve(self):
        ident=core.research_draft(self.db,self.admin,self.lead())
        with self.assertRaises(core.Rejected):
            core.approve(self.db,self.admin,ident,{'reviewed':True,'terms_approved':True})

    def test_service_cannot_read_or_approve_schedule(self):
        auth='Bearer '+'s'*40
        self.assertEqual(self.call('/api/outreach/state',authorization=auth)['status'],403)
        self.assertEqual(self.call('/api/outreach/leads','POST',{'company':'Test','email':'service@company.example','name':'Test','country':'Oman','website':'https://company.example'},authorization=auth)['status'],200)
        ident=self.message()
        for path in [f'/api/outreach/messages/{ident}/approve',f'/api/outreach/messages/{ident}/schedule','/api/outreach/pause']:
            self.assertEqual(self.call(path,'POST',{},authorization=auth)['status'],403)

    def test_csrf_required_and_secure_owner_login(self):
        cookie=self.login('senthil@test.example')
        me=json.loads(self.call('/api/outreach/me',cookie=cookie)['body'])
        self.assertEqual(self.call('/api/outreach/pause','POST',{'paused':True},cookie=cookie)['status'],403)
        self.assertEqual(self.call('/api/outreach/pause','POST',{'paused':True},cookie=cookie,csrf=me['csrf'])['status'],200)
        self.assertEqual(self.call('/auth/logout','POST',{},cookie=cookie,csrf=me['csrf'])['status'],200)
        self.assertEqual(self.call('/api/outreach/state',cookie=cookie)['status'],403)

    def test_login_rate_limit(self):
        for _ in range(8):
            self.assertEqual(self.call('/auth/login','POST',{'email':'missing@example.com','password':'bad'})['status'],401)
        self.assertEqual(self.call('/auth/login','POST',{})['status'],429)

    def test_duplicate_lead_and_first_contact(self):
        ident=self.message()
        with self.assertRaises(core.Rejected):
            core.add_lead(self.db,self.owner,{'company':'Duplicate','email':'Person0@Company.example','name':'Name','country':'UAE','website':'https://company.example'})
        second=core.research_draft(self.db,self.owner,core.get_message(self.db,ident)['lead_id'])
        with self.assertRaises(core.Rejected):
            core.approve(self.db,self.owner,second,{'reviewed':True,'terms_approved':True})

    def test_consent_and_source_required(self):
        lead=core.add_lead(self.db,self.owner,{'company':'Company','email':'someone@company.example','name':'Someone','country':'UAE','website':'https://company.example'})
        with self.assertRaises(core.Rejected):
            core.qualify(self.db,self.owner,lead,{'observation':'Something','evidence_url':'https://company.example','verified':True})
        draft=core.add_draft(self.db,self.owner,{'lead_id':lead,'subject':'Hello','body':'A short first contact.'})
        with self.assertRaises(core.Rejected):
            core.approve(self.db,self.owner,draft,{'reviewed':True,'terms_approved':True})

    def test_binding_terms_require_owner_exact_content_approval(self):
        ident=self.message()
        self.db.execute('UPDATE messages SET body=? WHERE id=?',('We guarantee delivery for USD 100.',ident))
        provider=FakeProvider()
        result=core.worker(self.db,provider,MONDAY)
        self.assertEqual(result['failed'],1)
        self.assertEqual(provider.calls,[])

    def test_review_acknowledgements_mandatory(self):
        ident=core.research_draft(self.db,self.owner,self.lead())
        with self.assertRaises(core.Rejected):
            core.approve(self.db,self.owner,ident,{'reviewed':True})

    def test_friday_pause_and_gulf_boundary(self):
        friday=int(datetime(2026,10,9,10,tzinfo=core.GULF).timestamp())
        saturday=int(datetime(2026,10,10,9,tzinfo=core.GULF).timestamp())
        self.assertFalse(core.window(friday))
        self.assertEqual(core.next_window(friday),saturday)
        self.assertEqual(core.next_window(int(datetime(2026,10,8,17,tzinfo=core.GULF).timestamp())),saturday)
        self.assertFalse(core.window(int(datetime(2026,10,5,8,59,tzinfo=core.GULF).timestamp())))
        self.assertTrue(core.window(saturday))
        ident=self.message()
        provider=FakeProvider()
        core.worker(self.db,provider,friday)
        self.assertEqual(provider.calls,[])
        self.assertEqual(core.get_message(self.db,ident)['state'],'queued')

    def test_retry_failure_isolation(self):
        first=self.message(0);second=self.message(1)
        provider=FakeProvider({first:Retryable('rate limit')})
        result=core.worker(self.db,provider,MONDAY)
        self.assertEqual(result['retry'],1);self.assertEqual(result['sent'],1)
        self.assertEqual(core.get_message(self.db,second)['state'],'sent')
        self.assertGreater(core.get_message(self.db,first)['retry_at'],MONDAY)
        provider.errors={}
        core.worker(self.db,provider,MONDAY+300)
        self.assertEqual(core.get_message(self.db,first)['state'],'sent')
        self.assertEqual(provider.calls.count(second),1)

    def test_uncertain_send_is_never_blindly_retried(self):
        ident=self.message()
        provider=FakeProvider({ident:TimeoutError('timeout')})
        core.worker(self.db,provider,MONDAY)
        core.worker(self.db,provider,MONDAY+1000)
        self.assertEqual(core.get_message(self.db,ident)['state'],'uncertain')
        self.assertEqual(len(provider.calls),1)

    def test_crash_lease_is_held(self):
        ident=self.message()
        self.db.execute("UPDATE messages SET state='sending',lease_until=? WHERE id=?",(MONDAY-1,ident))
        provider=FakeProvider();core.worker(self.db,provider,MONDAY)
        self.assertEqual(core.get_message(self.db,ident)['state'],'uncertain')
        self.assertEqual(provider.calls,[])

    def test_retry_limit(self):
        ident=self.message();self.db.execute('UPDATE messages SET attempts=4 WHERE id=?',(ident,))
        core.worker(self.db,FakeProvider({ident:Retryable('limit')}),MONDAY)
        self.assertEqual(core.get_message(self.db,ident)['state'],'failed')

    def test_permanent_failure_isolated(self):
        ident=self.message();second=self.message(1)
        result=core.worker(self.db,FakeProvider({ident:Permanent('rejected')}),MONDAY)
        self.assertEqual(result['failed'],1);self.assertEqual(result['sent'],1)

    def test_provider_disabled_preserves_queue(self):
        ident=self.message()
        result=core.worker(self.db,Mailgun(),MONDAY)
        self.assertIn('blocked',result)
        self.assertEqual(core.get_message(self.db,ident)['state'],'queued')

    def test_pause_preserves_queue(self):
        self.message();self.db.execute("UPDATE settings SET value='1' WHERE key='paused'")
        provider=FakeProvider();core.worker(self.db,provider,MONDAY)
        self.assertEqual(provider.calls,[])

    def test_bounce_suppresses_and_cancels_pending(self):
        ident=self.message();core.worker(self.db,FakeProvider(),MONDAY)
        event(self.db,self.payload(ident,'failed'))
        self.assertEqual(core.get_message(self.db,ident)['state'],'bounced')
        self.assertIsNotNone(self.db.execute('SELECT * FROM suppression').fetchone())
        event(self.db,self.payload(ident,'delivered'))
        self.assertEqual(core.get_message(self.db,ident)['state'],'bounced')

    def test_manual_suppression_blocks_queue(self):
        ident=self.message()
        with core.transaction(self.db):core.suppress(self.db,'person0@company.example','opt out')
        provider=FakeProvider();core.worker(self.db,provider,MONDAY)
        self.assertEqual(core.get_message(self.db,ident)['state'],'cancelled')
        self.assertEqual(provider.calls,[])

    def test_webhook_signature_and_duplicate(self):
        ident=self.message();core.worker(self.db,FakeProvider(),MONDAY)
        data=self.payload(ident)
        self.assertEqual(event(self.db,data),{'ok':True})
        self.assertEqual(event(self.db,data),{'duplicate':True})
        self.assertEqual(self.db.execute('SELECT count(*) FROM events').fetchone()[0],1)
        data['signature']['signature']='forged'
        with self.assertRaises(core.Rejected):event(self.db,data)

    def test_expired_signature_and_recipient_mismatch(self):
        ident=self.message();core.worker(self.db,FakeProvider(),MONDAY)
        data=self.payload(ident);data['event-data']['recipient']='other@company.example'
        with self.assertRaises(core.Rejected):event(self.db,data)
        data=self.payload(ident);data['signature']['timestamp']='1'
        with self.assertRaises(core.Rejected):event(self.db,data)

    def test_inbound_reply_cancels_queue_and_is_idempotent(self):
        ident=self.message()
        data=dict(self.signature(),sender='person0@company.example',recipient='reply@inbox.forgelaunch.test',subject='Interested',**{'Message-Id':'<incoming@example.com>','body-plain':'Please share details.'})
        self.assertEqual(inbound(self.db,data),{'ok':True})
        self.assertEqual(inbound(self.db,data),{'duplicate':True})
        self.assertEqual(core.get_message(self.db,ident)['state'],'cancelled')
        self.assertEqual(self.db.execute('SELECT state FROM leads').fetchone()[0],'replied')
        draft=core.add_draft(self.db,self.owner,{'lead_id':1,'kind':'reply','in_reply_to':'<incoming@example.com>','subject':'Re: Interested','body':'Happy to discuss.'})
        self.assertIsNotNone(draft)

    def test_unsubscribe_token_and_confirmation(self):
        from outreach.provider import unsubscribe_token
        ident=self.message();path=f'/unsubscribe/{ident}/{unsubscribe_token(ident)}'
        self.assertEqual(self.call(path)['status'],200)
        self.assertEqual(self.db.execute('SELECT count(*) FROM suppression').fetchone()[0],0)
        self.assertEqual(self.call(path,'POST')['status'],200)
        self.assertEqual(self.db.execute('SELECT count(*) FROM suppression').fetchone()[0],1)
        self.assertEqual(self.call(f'/unsubscribe/{ident}/fake','POST')['status'],403)

    def test_scheduled_in_future_not_sent(self):
        ident=self.message();self.db.execute('UPDATE messages SET retry_at=? WHERE id=?',(MONDAY+3600,ident))
        provider=FakeProvider();core.worker(self.db,provider,MONDAY)
        self.assertEqual(provider.calls,[])

    def test_length_and_header_injection(self):
        lead=self.lead()
        for subject,body in [('Test\r\nBcc: evil@example.com','Hello'),('Test','word '*181)]:
            with self.assertRaises(core.Rejected):core.add_draft(self.db,self.owner,{'lead_id':lead,'subject':subject,'body':body})

    def test_changed_payload_token_replay_rejected(self):
        ident=self.message();core.worker(self.db,FakeProvider(),MONDAY)
        data=self.payload(ident);event(self.db,data)
        data['event-data']['id']='forged-event'
        with self.assertRaises(core.Rejected):event(self.db,data)

    def test_daily_cap_includes_ambiguous_requests(self):
        ident=self.message()
        for _ in range(20):self.db.execute('INSERT INTO worker_attempts(message_id,created) VALUES(?,?)',(ident,MONDAY))
        provider=FakeProvider();core.worker(self.db,provider,MONDAY)
        self.assertEqual(provider.calls,[])

    def test_inbound_form_and_header_parsing(self):
        from urllib.parse import urlencode
        self.message()
        data=dict(self.signature(),sender='person0@company.example',recipient='reply@inbox.forgelaunch.test',subject='Hello',**{'message-headers':json.dumps([['Message-Id','<form@example.com>']]),'body-plain':'Hello'})
        raw=urlencode(data).encode();captured={}
        environ={'PATH_INFO':'/webhooks/mailgun/inbound','REQUEST_METHOD':'POST','CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/x-www-form-urlencoded','wsgi.input':io.BytesIO(raw)}
        def start(status,headers):captured['status']=int(status.split()[0])
        list(application(environ,start))
        self.assertEqual(captured['status'],200)
        self.assertEqual(self.db.execute('SELECT id FROM inbox').fetchone()[0],'<form@example.com>')

    def test_provider_request_shape_and_plain_text_unsubscribe(self):
        from urllib.parse import parse_qs
        self.message()
        message=core.get_message(self.db,1)
        lead=dict(self.db.execute('SELECT * FROM leads WHERE id=1').fetchone())
        class Response:
            def __enter__(self):return io.BytesIO(b'{"id":"<provider@example.test>"}')
            def __exit__(self,*args):pass
        with patch.dict(os.environ,{'MAILGUN_API_KEY':'synthetic-key','MAILGUN_DOMAIN':'mg.example.test'}):
            with patch('outreach.provider.urlopen',return_value=Response()) as send:
                self.assertEqual(Mailgun().send(message,lead),'<provider@example.test>')
                request=send.call_args[0][0]
                fields=parse_qs(request.data.decode())
                self.assertEqual(fields['to'],[lead['email']])
                self.assertEqual(fields['v:outreach_id'],['1'])
                self.assertIn('/unsubscribe/1/',fields['text'][0])
                self.assertEqual(fields['o:tracking'],['no'])
                self.assertEqual(request.full_url,'https://api.mailgun.net/v3/mg.example.test/messages')

    def test_production_cookie_secure_and_https_required(self):
        with patch.dict(os.environ,{'LOCAL_DEV':'false','PUBLIC_ORIGIN':'https://admin.example.test'}):
            raw=json.dumps({'email':'senthil@test.example','password':'A-long-local-test-password'}).encode()
            environ={'PATH_INFO':'/auth/login','REQUEST_METHOD':'POST','CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/json','wsgi.input':io.BytesIO(raw),'HTTP_ORIGIN':'https://admin.example.test','REMOTE_ADDR':'prod-test'}
            captured={}
            def start(status,headers):captured.update(status=status,headers=dict(headers))
            list(application(environ,start))
            self.assertTrue(captured['status'].startswith('200'))
            self.assertIn('; Secure',captured['headers']['Set-Cookie'])
            self.assertIn('HttpOnly',captured['headers']['Set-Cookie'])
        with patch.dict(os.environ,{'LOCAL_DEV':'false','PUBLIC_ORIGIN':'http://unsafe.test'}):
            self.assertEqual(self.call('/health')['status'],503)

    def test_two_workers_cannot_send_same_message(self):
        import threading
        ident=self.message()
        provider=FakeProvider()
        errors=[]
        def run():
            db=core.connect(self.path)
            try:core.worker(db,provider,MONDAY)
            except Exception as exc:errors.append(exc)
            finally:db.close()
        threads=[threading.Thread(target=run) for _ in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(errors,[])
        self.assertEqual(provider.calls,[ident])

    def gmail_config(self):
        return patch.dict(os.environ,{'EMAIL_PROVIDER':'gmail','GOOGLE_CLIENT_ID':'test-client.apps.googleusercontent.com','GOOGLE_CLIENT_SECRET':'synthetic-client-secret','GMAIL_ALLOWED_EMAIL':'forgelaunch.test@gmail.com'})

    def gmail_connection(self,expired=False):
        self.db.execute('INSERT INTO gmail_connection VALUES(1,?,?,?,?,?)',('forgelaunch.test@gmail.com','synthetic-refresh','synthetic-access',core.now()-10 if expired else core.now()+3600,'connected'))
        self.db.execute("INSERT INTO settings VALUES('gmail_instance','synthetic-instance')")

    def test_gmail_connect_owner_only_and_no_secrets_in_state(self):
        with self.gmail_config():
            cookie=self.login('senthil@test.example')
            me=json.loads(self.call('/api/outreach/me',cookie=cookie)['body'])
            response=self.call('/api/outreach/gmail/connect','POST',{},cookie=cookie,csrf=me['csrf'])
            self.assertEqual(response['status'],200)
            self.assertIn('SameSite=Lax',response['headers']['Set-Cookie'])
            self.assertIn('code_challenge',json.loads(response['body'])['authorization_url'])
            self.gmail_connection()
            state=self.call('/api/outreach/state',cookie=cookie)['body'].decode()
            self.assertNotIn('synthetic-refresh',state);self.assertNotIn('synthetic-access',state)
            client=self.login('client@test.example')
            self.assertEqual(self.call('/api/outreach/gmail/connect','POST',{},cookie=client)['status'],403)
            self.assertEqual(self.call('/api/outreach/gmail/disconnect','POST',{},authorization='Bearer '+'s'*40)['status'],403)

    def test_gmail_missing_credentials_connect_unavailable(self):
        with patch.dict(os.environ,{'GOOGLE_CLIENT_ID':'','GOOGLE_CLIENT_SECRET':''}):
            cookie=self.login('senthil@test.example')
            me=json.loads(self.call('/api/outreach/me',cookie=cookie)['body'])
            self.assertEqual(self.call('/api/outreach/gmail/connect','POST',{},cookie=cookie,csrf=me['csrf'])['status'],503)

    def test_oauth_state_session_binding_and_replay(self):
        from outreach.gmail import authorize,callback,SCOPES
        from urllib.parse import parse_qs,urlparse
        class Response:
            def __enter__(self):return io.BytesIO(b'{"emailAddress":"forgelaunch.test@gmail.com"}')
            def __exit__(self,*args):pass
        with self.gmail_config():
            url=authorize(self.db,self.owner,'owner-session')
            state=parse_qs(urlparse(url).query)['state'][0]
            tokens={'scope':' '.join(SCOPES),'access_token':'test-access','refresh_token':'test-refresh','expires_in':3600}
            with self.assertRaises(core.Rejected):callback(self.db,self.owner,'other-session',{'state':state,'code':'test-code'})
            with patch('outreach.gmail.token_request',return_value=tokens),patch('outreach.gmail.urlopen',return_value=Response()):
                callback(self.db,self.owner,'owner-session',{'state':state,'code':'test-code'})
            self.assertEqual(self.db.execute('SELECT email FROM gmail_connection').fetchone()[0],'forgelaunch.test@gmail.com')
            with self.assertRaises(core.Rejected):callback(self.db,self.owner,'owner-session',{'state':state,'code':'test-code'})

    def test_oauth_wrong_mailbox_is_not_connected(self):
        from outreach.gmail import authorize,callback,SCOPES
        from urllib.parse import parse_qs,urlparse
        class Response:
            def __enter__(self):return io.BytesIO(b'{"emailAddress":"wrong@gmail.com"}')
            def __exit__(self,*args):pass
        with self.gmail_config():
            state=parse_qs(urlparse(authorize(self.db,self.owner,'session')).query)['state'][0]
            tokens={'scope':' '.join(SCOPES),'access_token':'test-access','refresh_token':'test-refresh'}
            with patch('outreach.gmail.token_request',return_value=tokens),patch('outreach.gmail.urlopen',return_value=Response()):
                with self.assertRaises(core.Rejected):callback(self.db,self.owner,'session',{'state':state,'code':'test-code'})
            self.assertEqual(self.db.execute('SELECT count(*) FROM gmail_connection').fetchone()[0],0)

    def test_oauth_denial_and_insufficient_scope(self):
        from outreach.gmail import authorize,callback,SCOPES
        from urllib.parse import parse_qs,urlparse
        with self.gmail_config():
            for tokens,query in [({}, {'error':'access_denied'}),({'scope':SCOPES[0],'access_token':'test'}, {'code':'test'})]:
                state=parse_qs(urlparse(authorize(self.db,self.owner,'session')).query)['state'][0]
                with patch('outreach.gmail.token_request',return_value=tokens):
                    with self.assertRaises(core.Rejected):callback(self.db,self.owner,'session',dict(query,state=state))
            self.assertEqual(self.db.execute('SELECT count(*) FROM gmail_connection').fetchone()[0],0)

    def test_oauth_callback_requires_browser_binding(self):
        self.assertEqual(self.call('/auth/gmail/callback')['status'],403)

    def test_gmail_refresh_revocation_preserves_queue(self):
        from outreach.gmail import Gmail
        ident=self.message();self.gmail_connection(expired=True)
        with self.gmail_config(),patch.dict(os.environ,{'EMAIL_ENABLED':'true'}):
            with patch('outreach.gmail.token_request',side_effect=core.Rejected('Google authorization expired or was revoked. Reconnect Gmail.',503)):
                result=core.worker(self.db,Gmail(self.db),MONDAY)
            self.assertIn('blocked',result)
            self.assertEqual(core.get_message(self.db,ident)['state'],'queued')
            self.assertEqual(self.db.execute('SELECT status FROM gmail_connection').fetchone()[0],'reconnect_required')

    def test_gmail_refresh_and_send_mime(self):
        import base64
        from email.parser import BytesParser
        from email.policy import default
        from outreach.gmail import Gmail
        ident=self.message();self.gmail_connection(expired=True)
        gmail=Gmail(self.db)
        with self.gmail_config(),patch('outreach.gmail.token_request',return_value={'access_token':'refreshed','expires_in':3600}):
            gmail.prepare()
        self.assertEqual(self.db.execute('SELECT access_token FROM gmail_connection').fetchone()[0],'refreshed')
        with patch.object(gmail,'request',return_value={'id':'api-id','threadId':'thread-id'}) as send:
            result=gmail.send(core.get_message(self.db,ident),dict(self.db.execute('SELECT * FROM leads WHERE id=1').fetchone()))
        self.assertEqual(result,'gmail:api-id')
        raw=base64.urlsafe_b64decode(send.call_args[0][1]['raw'])
        mail=BytesParser(policy=default).parsebytes(raw)
        self.assertIn('forgelaunch.test@gmail.com',mail['From'])
        self.assertEqual(mail['To'],'person0@company.example')
        self.assertEqual(mail['Message-ID'],gmail.rfc_id(ident))
        self.assertIn('/unsubscribe/',mail.get_content())

    def test_gmail_only_imports_matching_outreach_thread(self):
        from outreach.gmail import Gmail
        from email.message import EmailMessage
        ident=self.message();self.gmail_connection();gmail=Gmail(self.db)
        mail=EmailMessage();mail['From']='person0@company.example';mail['Message-ID']='<reply@example.test>';mail['Subject']='Interested';mail.set_content('Please share an outline.')
        gmail.receive('incoming-api','unrelated-thread',mail)
        self.assertEqual(self.db.execute('SELECT count(*) FROM inbox').fetchone()[0],0)
        self.db.execute('INSERT INTO gmail_threads VALUES(?,?)',('outreach-thread',ident))
        gmail.receive('incoming-api','outreach-thread',mail);gmail.receive('incoming-api','outreach-thread',mail)
        self.assertEqual(self.db.execute('SELECT count(*) FROM inbox').fetchone()[0],1)
        self.assertEqual(core.get_message(self.db,ident)['state'],'cancelled')

    def test_gmail_permanent_dsn_requires_known_message_and_recipient(self):
        from outreach.gmail import Gmail
        from email.parser import BytesParser
        ident=self.message();self.gmail_connection();gmail=Gmail(self.db)
        self.db.execute("UPDATE messages SET state='sent',provider_id='gmail:sent' WHERE id=?",(ident,))
        raw=('MIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary="dsn"\r\n\r\n--dsn\r\nContent-Type: message/delivery-status\r\n\r\nOriginal-Message-ID: '+gmail.rfc_id(ident)+'\r\n\r\nFinal-Recipient: rfc822; person0@company.example\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n--dsn--\r\n').encode()
        gmail.bounce('dsn-id',BytesParser().parsebytes(raw))
        self.assertEqual(core.get_message(self.db,ident)['state'],'bounced')
        self.assertEqual(self.db.execute('SELECT count(*) FROM suppression').fetchone()[0],1)

    def test_gmail_unknown_acceptance_reconciles_without_resend(self):
        from outreach.gmail import Gmail
        ident=self.message();self.gmail_connection();gmail=Gmail(self.db)
        self.db.execute("UPDATE messages SET state='uncertain' WHERE id=?",(ident,))
        def response(path,data=None):
            if 'rfc822msgid' in path:return {'messages':[{'id':'sent-api','threadId':'sent-thread'}]}
            if path.startswith('threads/'):return {'messages':[]}
            return {'messages':[]}
        with self.gmail_config(),patch.object(gmail,'request',side_effect=response),patch.object(gmail,'send') as send:
            gmail.sync();send.assert_not_called()
        self.assertEqual(core.get_message(self.db,ident)['state'],'sent')

    def test_gmail_disconnect_removes_local_credentials(self):
        from outreach.gmail import disconnect
        self.gmail_connection()
        with patch('outreach.gmail.urlopen',side_effect=TimeoutError()):
            result=disconnect(self.db,self.owner)
        self.assertTrue(result['ok'])
        self.assertEqual(self.db.execute('SELECT count(*) FROM gmail_connection').fetchone()[0],0)

    def test_gmail_api_auth_failure_preserves_later_messages(self):
        from outreach.gmail import AuthorizationUnavailable
        first=self.message();second=self.message(1);self.gmail_connection()
        provider=FakeProvider({first:AuthorizationUnavailable('Reconnect Gmail')})
        core.worker(self.db,provider,MONDAY)
        self.assertEqual(core.get_message(self.db,first)['state'],'retry')
        self.assertEqual(core.get_message(self.db,second)['state'],'queued')
        self.assertEqual(provider.calls,[first])

    def test_google_callback_works_with_lax_binding_without_strict_cookie(self):
        from urllib.parse import parse_qs,urlparse,urlencode
        from outreach.gmail import SCOPES
        class Response:
            def __enter__(self):return io.BytesIO(b'{"emailAddress":"forgelaunch.test@gmail.com"}')
            def __exit__(self,*args):pass
        with self.gmail_config():
            cookie=self.login('senthil@test.example')
            me=json.loads(self.call('/api/outreach/me',cookie=cookie)['body'])
            connected=self.call('/api/outreach/gmail/connect','POST',{},cookie=cookie,csrf=me['csrf'])
            state=parse_qs(urlparse(json.loads(connected['body'])['authorization_url']).query)['state'][0]
            binding=connected['headers']['Set-Cookie'].split(';')[0]
            environ={'PATH_INFO':'/auth/gmail/callback','REQUEST_METHOD':'GET','QUERY_STRING':urlencode({'state':state,'code':'test-code'}),'HTTP_COOKIE':binding,'wsgi.input':io.BytesIO(b'')}
            captured={}
            def start(status,headers):captured.update(status=int(status.split()[0]),headers=dict(headers))
            tokens={'scope':' '.join(SCOPES),'access_token':'test-access','refresh_token':'test-refresh'}
            with patch('outreach.gmail.token_request',return_value=tokens),patch('outreach.gmail.urlopen',return_value=Response()):
                list(application(environ,start))
            self.assertEqual(captured['status'],302)
            self.assertEqual(captured['headers']['Location'],'/admin/outreach')


if __name__=='__main__':
    unittest.main()
