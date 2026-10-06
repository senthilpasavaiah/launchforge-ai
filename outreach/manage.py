import argparse
import getpass
import json
import os
import time
from outreach import core
from outreach.provider import Mailgun


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=['create-owner','worker','worker-once','serve','create-client'])
    parser.add_argument('--email')
    parser.add_argument('--port',type=int,default=8080)
    args=parser.parse_args()
    db=core.connect()
    if args.command.startswith('create-'):
        email=core.email_address(args.email or input('Email: '))
        password=getpass.getpass('Password (minimum 16 characters): ')
        role='owner' if args.command=='create-owner' else 'client'
        with core.transaction(db):
            if role=='owner' and db.execute("SELECT 1 FROM users WHERE role='owner'").fetchone():
                raise SystemExit('Owner already exists; use a secured database maintenance process for account recovery.')
            ident=db.execute('INSERT INTO users(email,name,role,password) VALUES(?,?,?,?)',(email,'Senthil' if role=='owner' else 'Client',role,core.password_hash(password))).lastrowid
            core.audit(db,'operator','account.created',ident)
        print('Account created.')
    elif args.command.startswith('worker'):
        while True:
            try:
                print(json.dumps(core.worker(db,Mailgun())),flush=True)
            except Exception as exc:
                print(json.dumps({'worker_error':type(exc).__name__}),flush=True)
            if args.command=='worker-once':
                break
            time.sleep(30)
    else:
        from wsgiref.simple_server import make_server
        from outreach.app import application
        if os.environ.get('LOCAL_DEV')!='true':
            raise SystemExit('Use gunicorn for production. Development server requires LOCAL_DEV=true.')
        print(f'Development server on http://127.0.0.1:{args.port}',flush=True)
        make_server('127.0.0.1',args.port,application).serve_forever()


if __name__=='__main__':
    main()
