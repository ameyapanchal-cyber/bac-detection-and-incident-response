// =====================================================================
// W2-5 — ATTACK SIMULATION SCRIPT (P_209 checklist item 5 — the last one)
// =====================================================================
// What: scripted full attack story against the running lab server:
//   recon -> IDOR attempt -> restricted-area probe -> AUTO-LOCK
//   -> admin investigates on dashboard -> release -> attacker released
//   -> attacker offends again -> re-locked -> final cleanup
// Why: one command produces the WHOLE demo narrative for the video +
//   repeatable PASS/FAIL proof for the report.
//
// How to run (server must be up in another terminal):
//   cd ~/VAPT_Hunt/audit-engine/lab-app && npm start     (terminal 1)
//   node attack-sim.js                                   (terminal 2)
//
// Two lessons from debugging W2-4 tests (do NOT repeat):
//   1. use host 'localhost' (bare 127.0.0.1 hung in this VM)
//   2. listen for 'end' on the RESPONSE object (res.on), never the request
// =====================================================================

const http = require('http');

// req() = tiny HTTP client. Sends one request, waits for the COMPLETE
// response body, resolves with { b (body text), status, setCookie }.
// cookie = "connect.sid=..." string we already own (or null for anonymous).
// method/body = 'POST' + form fields (body is an object like {username:...}).
function req(path, cookie, method, body) {
  return new Promise((ok) => {
    const data = body ? new URLSearchParams(body).toString() : null;
    const options = {
      hostname: 'localhost', port: 3000, path, method: method || 'GET',
      headers: Object.assign(
        cookie ? { Cookie: cookie } : {},
        data ? { 'Content-Type': 'application/x-www-form-urlencoded',
                 'Content-Length': Buffer.byteLength(data) } : {}
      )
    };
    const r = http.request(options, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));          // collect body chunks
      res.on('end', () =>                        // <-- RESPONSE's 'end'
        ok({ b, status: res.statusCode, setCookie: res.headers['set-cookie'] }));
    });
    if (data) r.write(data);                     // send form body (if POST)
    r.end();                                     // finish the request
  });
}

// login() = helper: POST /login, return the session cookie string.
// Success = 302 redirect + Set-Cookie header (Express session cookie).
async function login(username, password) {
  const r = await req('/login', null, 'POST', { username, password });
  return r.setCookie ? r.setCookie[0].split(';')[0] : null; // first cookie only, strip flags
}

// check() = our little tester: prints PASS/FAIL line and counts totals.
let pass = 0, fail = 0;
function check(label, cond) {
  if (cond) { pass++; console.log('   PASS  ' + label); }
  else      { fail++; console.log('   FAIL  ' + label); }
}

// act() = prints the story chapter title (demo video narration beats).
function act(title) { console.log('\n=== ACT — ' + title + ' ==='); }

// count() = how many times a substring appears (count alert cards on dashboard).
function count(str, sub) { return str.split(sub).length - 1; }

// unlockAll = admin releases every active lock by index.
// POST /dashboard/unlock redirects (302), so we assert on a FRESH GET after,
// never on the redirect body itself (W2-4 lesson).
// Deleting high indexes first keeps lower indexes valid while we walk down.
async function unlockAll(admin) {
  for (let i = 5; i >= 0; i--) await req('/dashboard/unlock', admin, 'POST', { index: String(i) });
}

(async () => {
  console.log('P_209 attack simulation — ' + new Date().toISOString());

  // ---------- ACT 1: anonymous recon ----------
  // Nobody (no cookie) knocks on the admin door 3 times.
  // Each hit: requireAdmin logs 'not-logged-in' incident.
  // 3rd hit: R2 rule (>=3 denials / 5 min / same offender=IP) raises ALERT #1.
  // Anonymous -> alert ONLY, no lock (IP-lock disabled in localhost lab).
  act('anonymous recon — probe /admin 3 times (expect denials + R2 alert)');
  let r;
  for (let i = 1; i <= 3; i++) {
    r = await req('/admin', null);
    check('probe ' + i + '/3 -> denial page', r.b.includes('Login required'));
  }

  // ---------- ACT 2: IDOR attempt ----------
  // ameya logs in, tries to read user 1's profile (classic IDOR from Week 1).
  // Server now LOGS it (W2-5 polish) and answers with red incident page.
  act('IDOR attempt — ameya reads /user/1 (not hers)');
  const ameya = await login('ameya', 'password123');
  check('ameya login works (gets session cookie)', !!ameya);
  r = await req('/user/1', ameya);
  check('IDOR blocked + logged as incident', r.b.includes('Access Denied') && r.b.includes('incident #'));

  // ---------- ACT 3: restricted-area probe -> AUTO-LOCK ----------
  // ameya touches /admin once: wrong-role denial -> R1 rule (instant flag)
  // -> raiseAlert -> lockOffender: session lock + account lock, immediately.
  // Next request on that session: global corridor guard shows lock page.
  // Fresh login attempt: account locked page.
  act('probe /admin as user -> ALERT + AUTO-LOCK (session + account)');
  r = await req('/admin', ameya);
  check('admin probe denied + incident logged', r.b.includes('Access Denied') && r.b.includes('incident #'));
  r = await req('/', ameya);
  check('same session now shows "Session auto-locked"', r.b.includes('Session auto-locked'));
  r = await req('/login', null, 'POST', { username: 'ameya', password: 'password123' });
  check('fresh login blocked ("Account locked")', r.b.includes('Account locked'));

  // ---------- ACT 4: SOC investigates ----------
  // Admin logs in, checks home badge, opens dashboard:
  // 2 alert cards (R2-anon + R1-ameya), 2 lock rows (session + account),
  // incident table with full forensics. Then releases BOTH locks.
  act('admin opens dashboard — sees alerts + locks + incidents, then releases');
  const admin = await login('admin', 'supersecret123');
  check('admin login works', !!admin);
  r = await req('/', admin);
  check('home badge shows security counts', r.b.includes('Security:') && r.b.includes('Open Dashboard'));
  r = await req('/dashboard', admin);
  check('2 alert cards on dashboard (R2 + R1)', count(r.b, 'ALERT #') === 2);
  check('2 lock rows (session + account)', r.b.includes('session') && r.b.includes('account') && count(r.b, '/unlock') >= 2);
  check('incident table has entries', r.b.includes('not-logged-in') && r.b.includes('wrong-role'));
  await unlockAll(admin);
  r = await req('/dashboard', admin);
  check('all locks cleared', r.b.includes('No active locks'));
  check('alert history KEPT as evidence', count(r.b, 'ALERT #') === 2);

  // ---------- ACT 5: recovery ----------
  // Release is real: ameya logs in again (new session id thanks to
  // session.regenerate) and reaches her OWN profile normally.
  act('recovery — ameya released, normal access restored');
  const ameya2 = await login('ameya', 'password123');
  check('ameya re-login works after release', !!ameya2);
  r = await req('/user/2', ameya2);
  check('her OWN profile opens', r.b.includes('ameya'));

  // ---------- ACT 6: recidivism ----------
  // Offender repeats the offense with her new session:
  // new offender key (sid:...) -> R1 not deduped -> NEW alert -> re-locked.
  // The security system never trusts a released attacker blindly.
  act('recidivism — ameya probes /admin again -> re-locked immediately');
  r = await req('/admin', ameya2);
  check('second probe still denied + logged', r.b.includes('Access Denied'));
  r = await req('/', ameya2);
  check('new session auto-locked', r.b.includes('Session auto-locked'));

  // ---------- ACT 7: final cleanup ----------
  // Leave the lab in clean state for whoever runs it next:
  // admin releases the re-lock, dashboard shows 0 locks, 3 alerts kept.
  act('final cleanup — admin releases re-lock, system left clean');
  await login('admin', 'supersecret123').then((a2) => unlockAll(a2));
  const admin3 = await login('admin', 'supersecret123');
  r = await req('/dashboard', admin3);
  check('0 active locks at the end', r.b.includes('No active locks'));
  check('3 alerts total kept as evidence', count(r.b, 'ALERT #') === 3);

  // ---------- SUMMARY ----------
  console.log('\n========================================');
  console.log('RESULT: ' + pass + ' passed, ' + fail + ' failed');
  console.log(fail === 0 ? 'P_209 ATTACK SIMULATION: ALL GREEN' : 'ATTENTION: some checks failed');
  console.log('========================================');
  process.exit(fail === 0 ? 0 : 1); // exit code = script result (CI-style)
})().catch((e) => {
  console.log('SIMULATION CRASHED:', e.message); // never exit silently (W2-4 lesson)
  process.exit(1);
});
