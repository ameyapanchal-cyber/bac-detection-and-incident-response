# Exercise 1 — SQL Injection in the login form

**Route:** `POST /login` · **Class:** CWE-89 (SQL Injection) · **OWASP:** A03:2021 — Injection
**Severity in the lab:** Critical (authentication bypass) · **Status:** ✅ broken, then fixed

---

## 1. Summary

The login endpoint built its SQL query by concatenating user input straight into the statement. An attacker could therefore alter the query's *logic* — not just its data — and authenticate as any account without knowing any password.

## 2. Mechanism (how it was broken)

Vulnerable version (input joined into the query string):

```js
const query = "SELECT * FROM users WHERE username = '" + username +
              "' AND password = '" + password + "'";
```

The classic bypass payload, submitted in the username field:

```
' OR 1=1--
```

After the closing quote, `OR 1=1` makes the WHERE condition true for **every** row, and `--` comments out the rest of the statement (including the password check):

```sql
SELECT * FROM users WHERE username = '' OR 1=1--' AND password = ''
                                                    ↑ everything after this is ignored
```

**Observed result:** the app logged the request in as `admin` — a full authentication bypass, with no password.

A second, subtler lesson came from the *fix* itself. A first attempt at parameterising the ID lookup produced this:

```js
db.get("SELECT * FROM users WHERE id = " + id, ...)   // still concatenation
```

Testing `id=1` "worked" but `id=2` returned nothing. The reason is SQL operator precedence: `id=2=2` is parsed as `id = (2=2)`, i.e. `id = 0`, which matches no row. It only *looked* like it worked for `1` because `1=1` evaluates to `1`. Joining user input into a query turns the input into **math**, not just a value — one more reason to bind parameters.

## 3. Evidence

| Step | Request | Result |
|---|---|---|
| 1 | `username=admin`, correct password | Login succeeds (baseline) |
| 2 | `username=' OR 1=1--`, any password | **Logged in as `admin`** — authentication bypass |
| 3 | `username=ameya'--`, any password | Logged in as `ameya` without the password |
| 4 | After fix: same payloads | `Login failed` — no bypass, normal login unaffected |

## 4. Remediation

Use **parameterised queries** — the driver sends the SQL and the values separately, so a value can never become syntax:

```js
const query = "SELECT * FROM users WHERE username = ? AND password = ?";
db.get(query, [username, password], (err, row) => { ... });
```

Why this works (and why a filter is not): the payload is now data, not code. Even a blacklist/WAF can be bypassed (parser differentials, encoding tricks), but a bound parameter cannot change the shape of the statement — the single fix that kills the whole class.

**Hardening also applied elsewhere in the app** — every query in the project uses `?` placeholders with a bound-parameter array:

| File | Query | Parameters |
|---|---|---|
| `db.js` | seed INSERT | literal (static, no user input) |
| `server.js` | `POST /login` | `[username, password]` |
| `server.js` | `GET /user/:id` | `[id]` |
| `server.js` | `POST /comment` | `[author, body]` |

## 5. Takeaway

> Injection is not a syntax trick — it is a **logic** problem. The moment user input can reach the *structure* of a query, the attacker owns the logic. Bind the values, let the driver own the syntax.
