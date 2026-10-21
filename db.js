// db.js — SQLite setup. Read this fully: it is the "database" half of the backend flow.
// Browser -> Express route (server.js) -> THIS file's queries -> users table.
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const os = require('os');
// The DB file lives in the OS temp folder, NOT in the project folder.
// Why: SQLite needs to lock its file while writing. On network/shared folders
// (VirtualBox shared folders, some cloud-sync dirs) that locking fails with
// "SQLITE_IOERR disk I/O error". The temp folder is always local + writable.
// Why os.tmpdir() and not a hardcoded '/tmp/lab.db': '/tmp' is Linux/macOS
// only — os.tmpdir() resolves per-OS (Windows: %TEMP%), so the app runs
// unchanged on a recruiter's Windows/Mac machine.
const db = new sqlite3.Database(path.join(os.tmpdir(), 'lab.db'));

db.serialize(() => {
  db.run('DROP TABLE IF EXISTS users');
  db.run('DROP TABLE IF EXISTS comments');
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    role TEXT
  )`);
  db.run(`CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT)`);
  // Seed data: 4 users.
  // 'admin'  = the defender (owner of /admin + /dashboard).
  // 'ameya'  = the recurring attacker in the demo story.
  // 'bob','guest' = extra demo identities — more offenders/traffic on the
  //   dashboard WITHOUT new attack surface (same rules, same response).
  // Note (known limitation, report): passwords stored plaintext — lab only.
  db.run(`INSERT INTO users (username, password, email, role)
          VALUES ('admin', 'supersecret123', 'admin@lab.local',    'admin'),
                 ('ameya', 'password123',   'ameya@lab.local',     'user'),
                 ('bob',   'bobpass123',    'bob@lab.local',       'user'),
                 ('guest', 'guestpass123',  'guest@lab.local',     'user')`);
});

module.exports = db;
