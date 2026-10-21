# Exercise 2 — IDOR on the profile endpoint

**Route:** `GET /user/:id` · **Class:** CWE-639 (Insecure Direct Object Reference) · **OWASP:** A01:2021 — Broken Access Control
**Severity in the lab:** High (cross-user data disclosure) · **Status:** ✅ broken, then fixed

---

## 1. Summary

The profile endpoint trusted the object identifier in the URL. Any logged-in user could read any other user's profile — including the admin's — simply by editing the number in the address bar. This is the canonical **horizontal** broken-access-control case, and the same class the later detection engine monitors.

## 2. Mechanism (how it was broken)

Vulnerable version — the URL number is the only thing that decides whose row is returned:

```js
app.get('/user/:id', (req, res) => {
  const id = req.params.id;
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, row) => {
    res.send(`<h2>${row.username}</h2><p>Email: ${row.email}</p>`);
  });
});
```

Two problems, one of them worse than the other:

1. **No authentication check** — even logged out, a request returned data.
2. **No ownership check** — logged in as `ameya` (id 2), a request for `/user/1` returned **the admin's email**. The session was never consulted; the URL alone decided.

The authentication bug is loud (you notice you are logged out). The authorisation bug is quiet — you are logged in, the page looks normal, and someone else's PII is on screen. That is why IDOR is the single highest-yield access-control bug class in real bug-bounty hunting.

## 3. Evidence — the 4-case matrix

| Case | Request | Expected (fixed) | Vulnerable behaviour |
|---|---|---|---|
| 1 | logged out → `/user/1` | `Login first` | admin's email (leak) |
| 2 | `ameya` → `/user/2` | ameya's own email | ameya's email (correct by luck) |
| 3 | `ameya` → `/user/1` | `Access Denied` | **admin's email (leak)** |
| 4 | `admin` → `/user/1` and `/user/2` | both (admin sees all) | both |

All four cases pass after the fix — a matrix, not a single happy path.

## 4. Remediation

Three checks, in order, each returning early:

```js
app.get('/user/:id', (req, res) => {
  if (!req.session.userId) {                 // 1. authentication
    return res.send('Login first');
  }
  const id = req.params.id;
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, row) => {
    if (!row) { return res.send('No user found'); }
    // 2. authorisation: own object, or the admin role
    if (row.id !== req.session.userId && req.session.role !== 'admin') {
      return res.send('Access Denied');
    }
    res.send(...);                            // 3. safe output (also XSS-escaped)
  });
});
```

**The text-vs-number trap.** The URL gives a *string* (`"1"`), the database row gives a *number* (`1`). A naive `row.id === req.params.id` fails for the right user and passes for the wrong one. The fix compares **book row against the session stamp** (`row.id !== req.session.userId` — both numbers), never URL against row.

**Why the role check is legitimate here.** Object-level access control says *the owner* may read the object. An administrator's account is an exception that has to be explicit — otherwise the admin role becomes a global read switch. The role lives in the session stamp (`req.session.role`), set at login, never in the URL.

## 5. Takeaway

> Never let a **client-supplied identifier** decide *whose* data you return. Authenticate, then compare the requested object against the **session**, and deny by default. IDOR is not an exotic bug — it is the *default* result of a route that never asks "is this person allowed to see this?"
