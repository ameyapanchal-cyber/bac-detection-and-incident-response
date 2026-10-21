// server.js — YOUR build zone. Boilerplate is given; the 3 vulnerable features are YOUR exercises.
// Each exercise: write it VULNERABLE first -> exploit with Burp -> fix -> note what changed.
// Run:  npm install && npm start   then open http://localhost:3000
const express = require('express');
const session = require('express-session');
const db = require('./db');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true })); // parses HTML form bodies into req.body
// W3 polish: serve static/theme.css. Mounted BEFORE session + lock guard so the
// stylesheet loads even for LOCKED users (their lock page is themed too).
app.use(express.static(path.join(__dirname, 'static')));
app.use(session({ secret: 'labsecret', resave: false, saveUninitialized: false }));

// escape() — HTML output escaping. Turns dangerous chars into safe text.
// < becomes &lt; so browser shows it as text, never runs it as HTML tag.
// This is THE fix for stored XSS: user input can no longer become real HTML.
function escape(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// W3 polish: same HTML skeleton for EVERY page — doctype, head, theme link.
// One place to change global structure; pages only contribute their inner body.
// (Keeps all page TEXT identical — attack-sim.js 21 checks must stay green.)
function page(title, inner) {
  return `<!doctype html><html><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escape(title)}</title>
    <link rel="stylesheet" href="/theme.css"></head>
    <body><div class="wrap">${inner}</div></body></html>`;
}

// ============ W2-2 — THE NOTEBOOK (detection logging) =======================
// P_209 "detect unauthorized access attempts": every DENIED hit gets one entry
// answering: who / what / when / why / from where / which session.
// 3 destinations: memory array (live) + incidents.log file (evidence) + terminal (demo).

const INCIDENTS_FILE = path.join(__dirname, 'incidents.log');
const incidentLog = []; // memory notebook — W2-3 rules + W2-4 dashboard read this

function logDenial(req, reason) {
  const entry = {
    time: new Date().toISOString(),
    who: req.session.username || 'nobody',
    userId: req.session.userId || null,
    role: req.session.role || 'none',
    method: req.method,
    url: req.originalUrl,
    reason, // 'not-logged-in' | 'wrong-role' (W2-3 adds more)
    ip: req.ip,
    sessionId: req.sessionID
  };
  incidentLog.push(entry);                                   // 1) memory — rules read this
  fs.appendFileSync(INCIDENTS_FILE, JSON.stringify(entry) + '\n'); // 2) file — survives restart
  console.log('🚨 DENIED', entry.who, entry.method, entry.url, '->', entry.reason); // 3) terminal
  detect(entry); // W2-3: run detection rules on every denial
  return entry;
}

// ============ W2-3 — DETECTION RULES (the brain) ============================
// Logging says "an attempt happened". Rules say "this PATTERN is an attack".
// Output = alerts[] (flagged attacks). W2-4 dashboard will display these.

const alerts = []; // flagged attacks — high-severity, W2-4 shows these on /dashboard

function offenderKey(e) {
  // who to group denials by: session for LOGGED-IN users, IP for anonymous
  // (nobody has no stable session — cookie not saved — so IP is the only thread)
  return e.userId ? 'sid:' + e.sessionId : 'ip:' + e.ip;
}

function raiseAlert(entry, rule, message) {
  const alert = {
    id: alerts.length + 1,
    time: entry.time,
    who: entry.who,
    offender: offenderKey(entry),
    url: entry.url,
    rule,        // which rule fired
    message,     // human sentence for the dashboard
    severity: 'HIGH'
  };
  alerts.push(alert);
  console.log(`🚨🚨 ALERT #${alert.id} [${rule}] ${alert.who}: ${message}`);
  lockOffender(alert, entry); // W2-4: alert triggers automatic incident response
  return alert;
}

function detect(entry) {
  // Rule 1 — INSTANT flag: logged-in non-admin touches /admin or /dashboard = intentional probe.
  // One hit is enough; honest users never knock on admin doors. Dashboard is ALSO
  // restricted (the security monitor must itself be protected + monitored).
  if (entry.reason === 'wrong-role' &&
      (entry.url.startsWith('/admin') || entry.url.startsWith('/dashboard'))) {
    const already = alerts.some(a => a.rule === 'R1-admin-probe' && a.offender === offenderKey(entry));
    if (!already) {
      raiseAlert(entry, 'R1-admin-probe', 'user-role session touched restricted area (instant flag)');
    }
  }
  // Rule 2 — PATTERN flag: >=3 denials from same offender within 5 minutes = probing attack.
  // Threshold kills "maybe mistake"; a real user doesn't hit denied doors 3 times.
  const WINDOW_MS = 5 * 60 * 1000;
  const key = offenderKey(entry);
  const recent = incidentLog.filter(e =>
    offenderKey(e) === key && (Date.now() - Date.parse(e.time)) < WINDOW_MS);
  if (recent.length >= 3) {
    const already = alerts.some(a => a.rule === 'R2-repeat-denials' && a.offender === key);
    if (!already) {
      raiseAlert(entry, 'R2-repeat-denials',
        recent.length + ' denials in 5 minutes from same ' + (entry.userId ? 'session' : 'IP') + ' — probing attack');
    }
  }
}

// ============ W2-4 — INCIDENT RESPONSE (auto-lock) ==========================
// HCL title's second half: "...and trigger immediate incident responses".
// Alert fires -> lock the offender NOW: session banned + account banned.
// Admin releases locks from /dashboard. (Anonymous/IP ban skipped in localhost
// lab: everyone shares 127.0.0.1 — one "ban" would lock the admin too. Real
// WAFs ban IPs; noted as limitation in report.)

const lockedSessions = new Set(); // sessionIDs banned from ALL pages
const lockedAccounts = new Set(); // userIds banned from even logging in
const locks = []; // history for dashboard table: {type, value, who, rule, alertId, time}

function lockOffender(alert, entry) {
  if (!entry.userId) {
    // anonymous offender: no stable session to lock; IP-lock disabled in lab
    console.log(`🚨🚨🚨 (no lock — anonymous offender, IP-lock disabled in localhost lab)`);
    return;
  }
  const add = (type, value) => {
    if (locks.some(l => l.type === type && String(l.value) === String(value))) return;
    locks.push({ type, value: String(value), who: entry.who, rule: alert.rule, alertId: alert.id, time: entry.time });
    if (type === 'session') lockedSessions.add(String(value));
    if (type === 'account') lockedAccounts.add(Number(value));
    console.log(`🚨🚨🚨 AUTO-LOCK [${type}:${value}] ${entry.who} by ${alert.rule}`);
  };
  add('session', entry.sessionId); // immediate: current browser dead
  add('account', entry.userId);    // persistent: can't even re-login until admin unlocks
}

// Global corridor guard: runs on EVERY request (after session parser, before all routes).
// Locked offender -> red lock page, never reaches any route.
// EXCEPTION (found by Ameya's manual test): /login and /logout must stay reachable —
// a locked browser must be able to switch identity (otherwise admin can never
// release it from the same browser; found the hard way when npm restart was
// the only escape). Analogy: a banned hostel guest can't enter any room, but
// the front counter stays open so someone else can vouch/switch.
app.use((req, res, next) => {
  if (req.path === '/login' || req.path === '/logout') return next(); // identity doors stay open
  if (lockedSessions.has(String(req.sessionID))) {
    return res.send(page('Session auto-locked', `<div class="lockpage">
      <h2>&#128274; Session auto-locked</h2>
      <p>Incident response was triggered. This session is blocked pending admin review.</p>
      <p><a href="/login">Switch user / login as admin &rarr;</a></p></div>`));
  }
  if (req.session.userId && lockedAccounts.has(Number(req.session.userId))) {
    return res.send(page('Account auto-locked', `<div class="lockpage">
      <h2>&#128274; Account auto-locked</h2>
      <p>Incident response was triggered. This account is blocked pending admin review.</p>
      <p><a href="/login">Switch user / login as admin &rarr;</a></p></div>`));
  }
  next();
});


// requireAdmin = the corridor guard for /admin. Checks + logs + answers.
// This is route-specific middleware: app.get('/admin', requireAdmin, handler)
function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    const entry = logDenial(req, 'not-logged-in');
    return res.send(page('Login required', `<div class="deny">
      <h2>&#9940; Login required</h2>
      <p>This attempt was blocked and logged as incident #${incidentLog.length}.</p></div>`));
  }
  if (req.session.role !== 'admin') {
    const entry = logDenial(req, 'wrong-role');
    return res.send(page('Access Denied', `<div class="deny">
      <h2>&#9940; Access Denied — admin only</h2>
      <p>This attempt was blocked and logged as incident #${incidentLog.length}.</p></div>`));
  }
  next(); // passed both checks — continue to the route handler
}

app.get('/', (req, res) => {
  // badge = admin-only visibility of security state (attacker never sees this)
  const badge = req.session.role === 'admin'
    ? `<div class="badge">&#9888; Security: <strong>${alerts.length}</strong> alert(s), <strong>${locks.length}</strong> active lock(s) — <a href="/dashboard">Open Dashboard</a></div>`
    : '';
  // "My profile" = the LOGGED-IN user's OWN id, never a hardcoded number
  // (was /user/2 = ameya — bob/guest clicking it got HER profile = Access Denied).
  const profileHref = req.session.userId ? '/user/' + req.session.userId : '/login';
  res.send(page('Vuln Lab', `
    <div class="nav">
      <a href="/">Home</a> | <a href="/login">Login</a> | <a href="${profileHref}">My profile</a>
      | <a href="/comments">Comments</a> | <a href="/admin">Admin</a>${req.session.userId ? ' | <a href="/logout">Logout</a>' : ''}
      <span class="who">Logged in as: ${escape(req.session.username) || 'nobody'}</span>
    </div>
    <h1><span class="dot"></span>Vuln Lab</h1>
    <div class="panel">
      <p>This app is the live target of the P_209 project: a restricted admin area
      monitored by a detection engine (every denial logged, patterns flagged,
      attacks auto-locked).</p>
      <p class="sub">Try the demo yourself: log in as the <strong>attacker</strong>
      (ameya) and touch the Admin link — watch the incident response fire.</p>
      ${badge}
    </div>
    <p class="foot">Training lab — authorized scope only. OWASP A01 incident response demo.</p>`));
});

// Logout — ends THIS session (W2-5b fix: without it there was no way to
// switch users in one browser). destroy() = delete the session on server side,
// then send cookie-less browser to the login form.
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});
app.get('/login', (req, res) => {
  res.send(page('Login', `<div class="login"><div class="panel">
    <h1><span class="dot"></span>Login</h1>
    <form method="POST" action="/login">
      <input type="text" name="username" placeholder="Username">
      <input type="password" name="password" placeholder="Password">
      <button type="submit">Login</button>
    </form>
    <div class="hint">demo accounts &nbsp;&bull;&nbsp; admin: admin / supersecret123 &nbsp;&bull;&nbsp; attacker: ameya / password123</div>
  </div><p class="foot">Training lab — authorized scope only.</p></div>`));

});

// ============ EXERCISE 1 — LOGIN (SQLi). Spec: ============================
// POST /login takes {username, password}, checks the users table, sets
// req.session.username + req.session.userId on success, redirects to /.
// WRITE IT VULNERABLE FIRST: build the query by concatenating input into the
// SQL string (you know this shape from SQLi M2: string vs numeric context).
// Then bypass it with ' OR 1=1--  (Burp), then fix with ? placeholders.
// TODO(ameya): implement POST /login here.
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const query = "SELECT * FROM users WHERE username = ?  AND password = ? ";

  db.get(query, [username, password], (err, row) => {
    if (!row) {
      return res.send(page('Login failed', `<div class="deny">
        <h2>&#9940; Login failed</h2>
        <p>Wrong username or password.</p></div>`));
    }
    if (lockedAccounts.has(Number(row.id))) {
      return res.send(page('Account locked', `<div class="lockpage">
        <h2>&#128274; Account locked</h2>
        <p>Account locked due to security incident. Contact admin.</p></div>`));
    }
    // regenerate = brand-new session ID before stamping.
    // Why: (1) W2-4 unlock works — old locked SID is abandoned; (2) real defense
    // called session-fixation protection: never keep a pre-login session ID.
    req.session.regenerate((err) => {
      req.session.username = row.username;
      req.session.userId = row.id;
      req.session.role = row.role;
      res.redirect('/');
    });
  });
});
// ============ EXERCISE 2 — PROFILE (IDOR). Spec: ==========================
// GET /user/:id returns that user's row (username + email).
// WRITE IT VULNERABLE FIRST: trust req.params.id directly, no ownership check.
// Then read user 1's email while logged in as user 2 (Burp), then fix by
// comparing req.params.id to req.session.userId (allow admin role).
// TODO(ameya): implement GET /user/:id here.
app.get('/user/:id', (req, res) => {
  if (!req.session.userId) {
    return res.send('Login first');
  }
  const id = req.params.id;
  const query = "SELECT * FROM users WHERE id = ?";

  db.get(query, [id], (err, row) => {
    if (!row) {
      return res.send('No user found');
    }
    if (row.id !== req.session.userId && req.session.role !== 'admin') {
      // W2-5: IDOR attempt is now a LOGGED incident too (P_209: restricted areas)
      const entry = logDenial(req, 'wrong-role');
      return res.send(page('Access Denied', `<div class="deny">
        <h2>&#9940; Access Denied</h2>
        <p>This attempt was blocked and logged as incident #${incidentLog.length}.</p></div>`));
    }
    res.send(page('Profile', `<h1><span class="dot"></span>Profile</h1>
      <div class="panel"><h2 style="border:none;margin:8px 0 2px">${escape(row.username)}</h2>
      <p class="sub">Email: ${escape(row.email)}</p></div>
      <a href="/">&larr; Back home</a>`));
  });
});
// ============ EXERCISE 3 — COMMENTS (stored XSS). Spec: ====================
// GET /comments shows a form + all comments. POST /comment saves {author, body}.
// WRITE IT VULNERABLE FIRST: insert body into the HTML with no escaping.
// Then store <img src=x onerror=alert(1)> and watch it fire on reload (you
// know this payload from XSS Day16), then fix by escaping < > & " ' on output.
// TODO(ameya): implement GET /comments + POST /comment here.

app.get('/comments', (req, res) => {
  const query = "SELECT * FROM comments";

  db.all(query, (err, rows) => {
    let commentsHtml = "";
    for (const row of rows) {
      // escape() on both fields — payload stays as TEXT, never becomes HTML
      commentsHtml += `<div class="comment">
        <strong>${escape(row.author)}</strong>
        <p>${escape(row.body)}</p>
      </div>`;
    }

    res.send(page('Comments', `<h1><span class="dot"></span>Comments</h1>
      <div class="panel tight">
      <form method="POST" action="/comment" class="inline">
        <input type="text" name="body" placeholder="Your comment" style="min-width:60%">
        <button type="submit">Post</button>
      </form></div>
      <hr>
      ${commentsHtml || '<p class="sub">No comments yet.</p>'}
      <p><a href="/">&larr; Back home</a></p>`));
  });
});

app.post('/comment', (req, res) => {
  // bonus fix: server already knows WHO from session stamp — no name box needed
  const author = req.session.username || 'nobody';
  const body = req.body.body;

  const query = "INSERT INTO comments (author, body) VALUES (?, ?)";
  db.run(query, [author, body], (err) => {
    res.redirect('/comments');
  });
});

// ============ W2-1 — RESTRICTED AREA /admin (the trap room) =================
// P_209 step 1: the restricted area unauthorized users will TRY to reach.
// Checks moved to requireAdmin middleware (W2-2) — handler only serves content.
app.get('/admin', requireAdmin, (req, res) => {
  res.send(page('Admin Area', `<h1><span class="dot"></span>Admin Area</h1>
    <div class="panel">
      <p>Welcome, admin (${escape(req.session.username)}).</p>
      <p>This is the restricted zone. Unauthorized hits here = incident.</p>
      <p><a href="/dashboard">&#128737; Security Dashboard &rarr;</a></p>
    </div>
    <a href="/">&larr; Back home</a>`));
});

// ============ W2-4 — SECURITY DASHBOARD (where admin sees everything) =======
// Admin-only view of alerts[] + locks[] + incidentLog[]. This answers the
// original question: "where and who can see the alerts" — HERE, admin role only.
app.get('/dashboard', requireAdmin, (req, res) => {
  const alertCards = alerts.slice().reverse().map(a => `
    <div class="alert-card">
      <div class="atitle">&#128680; ALERT #${a.id} &nbsp;[${escape(a.rule)}] &nbsp;severity: ${a.severity}</div>
      <div>${escape(a.message)}</div>
      <small>who: ${escape(a.who)} | offender: ${escape(a.offender)} | url: ${escape(a.url)} | ${a.time}</small>
    </div>`).join('') || '<p class="sub">No active alerts.</p>';

  const lockRows = locks.map((l, i) => `
    <tr>
      <td><strong>${escape(l.type)}</strong></td><td>${escape(l.value)}</td><td>${escape(l.who)}</td>
      <td>${escape(l.rule)}</td><td>${l.time}</td>
      <td><form method="POST" action="/dashboard/unlock" class="inline">
        <input type="hidden" name="index" value="${i}">
        <button type="submit" class="ghost">Release</button></form></td>
    </tr>`).join('') || '<tr><td colspan="6">No active locks.</td></tr>';

  const incidentRows = incidentLog.slice(-20).reverse().map(e => `
    <tr>
      <td>${e.time}</td><td>${escape(e.who)}</td><td>${escape(e.method + ' ' + e.url)}</td>
      <td>${escape(e.reason)}</td><td>${escape(e.ip)}</td><td>${escape(String(e.sessionId).slice(0, 12))}…</td>
    </tr>`).join('') || '<tr><td colspan="6">No incidents recorded.</td></tr>';

  res.send(page('Security Dashboard', `
    <div class="nav">
      <a href="/">Home</a> | <a href="/admin">Admin area</a> | <a href="/logout">Logout</a>
      <span class="who">SOC — signed in as ${escape(req.session.username)}</span>
    </div>
    <h1><span class="dot"></span>Security Dashboard</h1>
    <p class="sub">Alerts: <strong>${alerts.length}</strong> &nbsp;|&nbsp; Active locks: <strong>${locks.length}</strong> &nbsp;|&nbsp; Incidents: <strong>${incidentLog.length}</strong></p>
    <h2>Alerts — attacks flagged by rules</h2>
    ${alertCards}
    <h2>Active locks — incident response</h2>
    <table>
      <tr><th>Type</th><th>Value</th><th>Who</th><th>Rule</th><th>Time</th><th>Action</th></tr>
      ${lockRows}
    </table>
    <h2>Incidents — last 20 denials</h2>
    <table>
      <tr><th>Time</th><th>Who</th><th>Request</th><th>Reason</th><th>IP</th><th>Session</th></tr>
      ${incidentRows}
    </table>
    <p class="foot">Training lab — authorized scope only. Evidence file: incidents.log</p>`));
});

// Admin releases a lock (incident closed by human decision)
app.post('/dashboard/unlock', requireAdmin, (req, res) => {
  const idx = Number(req.body.index);
  const lock = locks[idx];
  if (lock) {
    if (lock.type === 'session') lockedSessions.delete(String(lock.value));
    if (lock.type === 'account') lockedAccounts.delete(Number(lock.value));
    locks.splice(idx, 1);
    console.log('🔓 UNLOCKED', lock.type + ':' + lock.value, 'by admin');
  }
  res.redirect('/dashboard');
});

app.listen(3000, () => console.log('Vuln lab on http://localhost:3000'));