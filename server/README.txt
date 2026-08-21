Phantom.wtf — Server-side auth + Loader
=======================================

WHY
---
The .dll is no longer next to a public download.
It lives only on your server under server/private/ and is streamed
to the loader AFTER email/password login + active subscription.

ROLES
-----
owner  — full power (change roles, everything)
admin  — keys, extend, revoke
helper — auto +20 days every 30 days
vip    — auto +3 days every 60 days
user   — week ($4) / month ($9) keys only

SERVER
------
cd server
npm install
# copy your velocity.dll -> server/private/velocity.dll
node server.js

Default owner:
  axion@phantom.wtf / PhantomOwner#2026

LOADER
------
1. Open loader/src/main.cpp
2. Set k_api_host / k_api_port to your VPS (and k_api_https = true if TLS)
3. Build PhantomLoaderAuth.vcxproj (Release | x64)
4. Ship ONLY PhantomLoader.exe to users (no dll)

Loader pages:
  - Login: email, password, Remember me
  - Main: User / Role / Expires + LAUNCH
    LAUNCH validates session, downloads module from API, waits 35s, injects

ANTI-CRACK (practical)
----------------------
- No public DLL
- JWT session required every launch
- Server checks sub_active before payload
- Staff roles enforced server-side
- Remember-me only stores token locally (revokable by changing JWT secret)

Wire the website js/store.js to this API for production (replace localStorage).
