Phantom.wtf Auth Server
=======================

1) Put velocity.dll into server/private/velocity.dll  (never publish this folder)
2) npm install
3) node server.js
   Default: http://127.0.0.1:8787

Owner (seeded):
  email: axion@phantom.wtf
  pass:  PhantomOwner#2026

Env overrides:
  PHANTOM_PORT, PHANTOM_JWT, PHANTOM_OWNER_EMAIL, PHANTOM_OWNER_PASS, PHANTOM_DLL

Roles
-----
owner  - full power (role changes, everything)
admin  - create keys, extend/revoke users
helper - +20 days subscription every 30 days (auto)
vip    - +3 days every 60 days (auto)
user   - normal paid week/month keys

Loader flow
-----------
Login (email/pass) -> /api/login
Session -> /api/loader/session  (shows user, role, expire)
Inject  -> /api/loader/payload  streams DLL only if sub active
DLL is never a public file on the website.
