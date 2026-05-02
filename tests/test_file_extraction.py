"""Unit tests for HTTP file-transfer detection helpers."""
import base64
import hashlib
import re

# Replicate the extraction logic from analyze_pcap() for unit testing

_FILE_MIME_PREFIXES = (
    "application/", "image/", "audio/", "video/",
    "text/csv", "text/xml", "text/plain",
)
_FILE_MIME_SKIP = {
    "text/html", "text/css", "text/javascript",
    "application/json", "application/javascript",
    "application/x-www-form-urlencoded",
}


def _extract_file(payload: bytes):
    """Return (filename, mime, size, sha256) or None from an HTTP response payload."""
    if not payload or not payload.startswith(b"HTTP/"):
        return None
    sep = payload.find(b"\r\n\r\n")
    if sep == -1:
        return None
    hdr_raw = payload[:sep].decode("utf-8", errors="replace")
    body = payload[sep + 4:]
    mime = ""
    filename = ""
    clen = None
    for hl in hdr_raw.split("\r\n")[1:]:
        if ":" not in hl:
            continue
        hk, hv = hl.split(":", 1)
        hk_l = hk.strip().lower()
        hv_s = hv.strip()
        if hk_l == "content-type":
            mime = hv_s.split(";")[0].strip().lower()
        elif hk_l == "content-disposition":
            fnm = re.search(r'filename\*?=["\']?([^"\';\r\n]+)', hv_s, re.IGNORECASE)
            if fnm:
                filename = fnm.group(1).strip().strip("\"'")[:200]
        elif hk_l == "content-length":
            try:
                clen = int(hv_s)
            except ValueError:
                pass
    interesting = filename or (
        mime and any(mime.startswith(p) for p in _FILE_MIME_PREFIXES)
        and mime not in _FILE_MIME_SKIP
    )
    if not interesting or not body:
        return None
    sha = hashlib.sha256(body).hexdigest()
    size = clen if clen is not None else len(body)
    return filename, mime, size, sha


def _make_response(status="200 OK", headers=None, body=b"data"):
    h = f"HTTP/1.1 {status}\r\n"
    for k, v in (headers or {}).items():
        h += f"{k}: {v}\r\n"
    return h.encode() + b"\r\n" + body


class TestFileExtraction:
    def test_pdf_content_type(self):
        payload = _make_response(
            headers={"Content-Type": "application/pdf", "Content-Length": "4"},
            body=b"%PDF",
        )
        result = _extract_file(payload)
        assert result is not None
        fname, mime, size, sha = result
        assert mime == "application/pdf"
        assert size == 4
        assert sha == hashlib.sha256(b"%PDF").hexdigest()

    def test_content_disposition_attachment(self):
        payload = _make_response(
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Disposition": 'attachment; filename="malware.exe"',
            },
            body=b"MZ\x90\x00",
        )
        result = _extract_file(payload)
        assert result is not None
        fname, mime, size, sha = result
        assert fname == "malware.exe"

    def test_html_skipped(self):
        payload = _make_response(
            headers={"Content-Type": "text/html; charset=utf-8"},
            body=b"<html></html>",
        )
        assert _extract_file(payload) is None

    def test_json_skipped(self):
        payload = _make_response(
            headers={"Content-Type": "application/json"},
            body=b'{"ok":true}',
        )
        assert _extract_file(payload) is None

    def test_image_detected(self):
        body = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        payload = _make_response(
            headers={"Content-Type": "image/png"},
            body=body,
        )
        result = _extract_file(payload)
        assert result is not None
        _, mime, _, _ = result
        assert mime == "image/png"

    def test_zip_detected(self):
        body = b"PK\x03\x04" + b"\x00" * 20
        payload = _make_response(
            headers={"Content-Type": "application/zip"},
            body=body,
        )
        result = _extract_file(payload)
        assert result is not None

    def test_not_http_response_skipped(self):
        payload = b"GET /file HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert _extract_file(payload) is None

    def test_no_separator_skipped(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf"
        assert _extract_file(payload) is None

    def test_empty_body_skipped(self):
        payload = _make_response(
            headers={"Content-Type": "application/pdf"},
            body=b"",
        )
        assert _extract_file(payload) is None

    def test_filename_with_quotes_stripped(self):
        payload = _make_response(
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Disposition": 'attachment; filename="report.pdf"',
            },
            body=b"data",
        )
        result = _extract_file(payload)
        assert result is not None
        fname, _, _, _ = result
        assert fname == "report.pdf"

    def test_content_length_used_for_size(self):
        payload = _make_response(
            headers={"Content-Type": "application/zip", "Content-Length": "999"},
            body=b"PK",
        )
        result = _extract_file(payload)
        assert result is not None
        _, _, size, _ = result
        assert size == 999

    def test_sha256_correctness(self):
        body = b"hello world"
        payload = _make_response(
            headers={"Content-Type": "application/octet-stream"},
            body=body,
        )
        result = _extract_file(payload)
        assert result is not None
        _, _, _, sha = result
        assert sha == hashlib.sha256(body).hexdigest()
