# Exercise 3 — Stored XSS in the comments feature

**Route:** `GET /comments` + `POST /comment` · **Class:** CWE-79 (Stored XSS) · **OWASP:** A03:2021 — Injection
**Severity in the lab:** High (persistent script execution for every visitor) · **Status:** ✅ broken, then fixed

---

## 1. Summary

Comments were stored raw and rendered straight into the page's HTML. A payload saved once by any user executed in **every** visitor's browser on every page load — a persistent (stored) cross-site scripting hole.

## 2. Mechanism (how it was broken)

Vulnerable sink — the comment body inserted into HTML with no sanitisation:

```js
commentsHtml += `<div class="comment">
  <strong>${row.author}</strong>
  <p>${row.body}</p>          // ← user input becomes HTML
</div>`;
```

Payload used (classic Day-16 payload from the XSS playbook):

```html
<img src=x onerror=alert(1)>
```

The browser finds an invalid image source, fails to load it, and fires the `onerror` handler — so the script runs even though no valid image exists.

**Why stored XSS is worse than reflected:** the payload is **persisted in the database**. One submission, every later visitor is affected, and the payload is invisible to the victim because it never appears in the URL.

## 3. Evidence — 10-payload battery

Every payload was posted in one server lifetime, then the rendered page was inspected:

| # | Payload (attack class) | Result after fix |
|---|---|---|
| 1 | `<img src=x onerror=alert(1)>` (event handler) | ✅ stored as text |
| 2 | `"><script>alert(1)</script>` (tag break-out) | ✅ |
| 3 | `';alert(1)//` (JS string break-out) | ✅ |
| 4 | `javascript:alert(1)` (URL scheme) | ✅ |
| 5 | `${alert(1)}` (template literal) | ✅ literal `${alert(1)}` |
| 6 | `{{7*7}}` (Angular interpolation) | ✅ literal `{{7*7}}` |
| 7 | `</script><script>` (layer jump) | ✅ |
| 8 | `&lt;script&gt;` (entity smuggling) | ✅ `&` escaped first |
| 9 | `<<script>` (decoy / broken-sanitizer class) | ✅ `/g` global replace |
| 10 | `\";alert(1)//` (backslash escape) | ✅ |

**Verdict: 10/10 defended** — zero executable HTML in the response; all ten appear as visible text. Additional checks: no `<script>` tags anywhere in the app (so no DOM-XSS sink exists), and the session cookie is `HttpOnly` (a stolen DOM value still cannot read it).

## 4. Remediation

A single `escape()` helper applied at **every output sink**:

```js
function escape(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')      // & FIRST — otherwise &lt; becomes &amp;lt; (entity smuggling)
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```

Sinks covered: comment body, comment author, profile username, profile email, the logged-in name on the home page, and every alert/lock/incident field rendered on the dashboard.

**The three details that make escaping actually hold:**

1. **Escape `&` first.** Otherwise a user typing `&lt;script&gt;` gets `&amp;lt;script&amp;gt;` — fine — but a user typing `&lt;` after `&` is already replaced would produce `&amp;lt;`, and naive ordering lets entity smuggling through. `&` must be replaced before the other four.
2. **Use the `/g` flag.** Without it only the *first* occurrence in a string is replaced — a payload like `<<script>` survives. A broken-sanitizer class of bug that only shows up with a second occurrence.
3. **Escape on OUTPUT, store raw in the DB.** The database keeps the real payload (an admin can audit what was submitted); the browser only ever receives safe text.

**Bonus fix found while breaking it (a second access-control bug):** the comment form originally had a *name* box, and the server trusted whatever the client typed as the author. The server already knows who is logged in from the session stamp, so the field was deleted and the author is now stamped server-side:

```js
const author = req.session.username || 'nobody';   // never trust the client to say who they are
```

## 5. Takeaway

> Sanitise **on output**, not on input — and encode for the *context* you are writing into. Escaping is not "block `<script>`": it is "make the browser show these characters instead of executing them". And if the server already knows the user's identity, **never accept it from the client**.
