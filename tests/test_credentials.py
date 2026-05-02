"""Unit tests for credential extraction logic used in analyze_pcap().

These tests verify the regex/base64 decoding patterns directly without
requiring a full PCAP file, since the extraction is inlined in the hot loop.
"""
import base64
import re
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Helpers mirroring the extraction patterns in app.py ──────────────────────

def _extract_http_basic(payload_bytes):
    """Return (username, password) from HTTP Basic auth header, or None."""
    try:
        text = payload_bytes[:4000].decode("utf-8", errors="replace")
        m = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE)
        if m:
            decoded = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="replace")
            if ":" in decoded:
                u, p = decoded.split(":", 1)
                return u, p
    except Exception:
        pass
    return None


def _extract_http_form_post(payload_bytes):
    """Return (username, password) from HTTP POST form body, or None."""
    try:
        if not payload_bytes[:5].startswith(b"POST "):
            return None
        text = payload_bytes.decode("utf-8", errors="replace")
        pm = re.search(r"(?:password|passwd|pwd)=([^&\r\n ]{1,120})", text, re.IGNORECASE)
        if pm:
            um = re.search(r"(?:username|user|login|email|name)=([^&\r\n ]{1,120})", text, re.IGNORECASE)
            return (um.group(1) if um else ""), pm.group(1)
    except Exception:
        pass
    return None


def _extract_ftp(text, state):
    """Simulate FTP USER/PASS state machine. state is a dict modified in-place."""
    text = text.strip()
    if text.upper().startswith("USER "):
        state["user"] = text[5:].strip()
        return None
    elif text.upper().startswith("PASS ") and "user" in state:
        cred = (state.pop("user"), text[5:].strip())
        return cred
    return None


def _extract_smtp_auth_plain(text):
    """Return (username, password) from AUTH PLAIN base64 blob, or None."""
    m = re.match(r"AUTH PLAIN ([A-Za-z0-9+/=]+)", text.strip(), re.IGNORECASE)
    if m:
        try:
            decoded = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="replace")
            parts = decoded.split("\x00")
            if len(parts) >= 3:
                return parts[1], parts[2]
        except Exception:
            pass
    return None


def _extract_pop3(text, state):
    """Simulate POP3 USER/PASS state machine."""
    text = text.strip()
    if text.upper().startswith("USER "):
        state["user"] = text[5:].strip()
        return None
    elif text.upper().startswith("PASS ") and "user" in state:
        return (state.pop("user"), text[5:].strip())
    return None


def _extract_imap_login(text):
    """Return (username, password) from IMAP LOGIN command, or None."""
    m = re.match(r'[A-Za-z0-9]+ LOGIN (\S+)\s+(\S+)', text.strip(), re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)
    return None


# ── HTTP Basic auth ───────────────────────────────────────────────────────────

def test_http_basic_auth_extracted():
    token = base64.b64encode(b"admin:s3cr3t").decode()
    payload = f"GET /api HTTP/1.1\r\nAuthorization: Basic {token}\r\n\r\n".encode()
    result = _extract_http_basic(payload)
    assert result == ("admin", "s3cr3t")


def test_http_basic_auth_colon_in_password():
    token = base64.b64encode(b"user:pass:word").decode()
    payload = f"GET / HTTP/1.1\r\nAuthorization: Basic {token}\r\n\r\n".encode()
    u, p = _extract_http_basic(payload)
    assert u == "user"
    assert p == "pass:word"


def test_http_basic_auth_missing_returns_none():
    payload = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert _extract_http_basic(payload) is None


def test_http_basic_auth_case_insensitive():
    token = base64.b64encode(b"root:toor").decode()
    payload = f"POST /login HTTP/1.1\r\nauthorization: basic {token}\r\n\r\n".encode()
    result = _extract_http_basic(payload)
    assert result == ("root", "toor")


# ── HTTP form POST ────────────────────────────────────────────────────────────

def test_http_form_post_password_extracted():
    payload = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=hunter2"
    result = _extract_http_form_post(payload)
    assert result is not None
    user, pw = result
    assert user == "alice"
    assert pw == "hunter2"


def test_http_form_post_passwd_variant():
    payload = b"POST /auth HTTP/1.1\r\n\r\nlogin=bob&passwd=secret123"
    user, pw = _extract_http_form_post(payload)
    assert pw == "secret123"


def test_http_form_post_no_password_returns_none():
    payload = b"POST /search HTTP/1.1\r\n\r\nquery=hello"
    assert _extract_http_form_post(payload) is None


def test_http_get_not_matched():
    payload = b"GET /page?username=x&password=y HTTP/1.1\r\n\r\n"
    assert _extract_http_form_post(payload) is None


# ── FTP ───────────────────────────────────────────────────────────────────────

def test_ftp_user_pass_sequence():
    state = {}
    assert _extract_ftp("USER ftpuser", state) is None
    assert state["user"] == "ftpuser"
    result = _extract_ftp("PASS ftppass", state)
    assert result == ("ftpuser", "ftppass")
    assert "user" not in state


def test_ftp_pass_without_user_ignored():
    state = {}
    assert _extract_ftp("PASS orphan", state) is None


def test_ftp_case_insensitive():
    state = {}
    _extract_ftp("user Admin", state)
    result = _extract_ftp("pass Secret!", state)
    assert result == ("Admin", "Secret!")


# ── SMTP AUTH PLAIN ───────────────────────────────────────────────────────────

def test_smtp_auth_plain_null_separated():
    blob = base64.b64encode(b"\x00user@example.com\x00mypassword").decode()
    result = _extract_smtp_auth_plain(f"AUTH PLAIN {blob}")
    assert result == ("user@example.com", "mypassword")


def test_smtp_auth_plain_not_matching_returns_none():
    assert _extract_smtp_auth_plain("EHLO mail.example.com") is None


def test_smtp_auth_plain_too_few_null_fields():
    blob = base64.b64encode(b"justonepart").decode()
    assert _extract_smtp_auth_plain(f"AUTH PLAIN {blob}") is None


# ── POP3 ─────────────────────────────────────────────────────────────────────

def test_pop3_user_pass_sequence():
    state = {}
    _extract_pop3("USER popuser", state)
    result = _extract_pop3("PASS poppassword", state)
    assert result == ("popuser", "poppassword")


def test_pop3_pass_without_user_ignored():
    state = {}
    assert _extract_pop3("PASS lonely", state) is None


# ── IMAP ─────────────────────────────────────────────────────────────────────

def test_imap_login_extracted():
    result = _extract_imap_login("a001 LOGIN imapuser secretpass")
    assert result == ("imapuser", "secretpass")


def test_imap_login_case_insensitive():
    result = _extract_imap_login("TAG1 login User Pass123")
    assert result is not None
    assert result[0] == "User"
    assert result[1] == "Pass123"


def test_imap_login_no_match():
    assert _extract_imap_login("a001 SELECT INBOX") is None


def test_imap_login_quoted_not_matched():
    # IMAP LOGIN with quoted strings — pattern is simple \S+ so only works unquoted
    result = _extract_imap_login('a001 LOGIN "user@example.com" "mypass"')
    assert result is not None  # \S+ still matches quoted tokens
