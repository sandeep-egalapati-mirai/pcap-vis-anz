"""HTTP-layer tests for the /upload endpoint."""
import io
import sys
import os
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module
from app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


# ── /upload happy path ────────────────────────────────────────────────────────

# Minimal pcap file: 24-byte global header (little-endian) with no packets.
_PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1"  # magic (little-endian)
    b"\x02\x00\x04\x00"  # version 2.4
    b"\x00\x00\x00\x00"  # timezone
    b"\x00\x00\x00\x00"  # timestamp accuracy
    b"\xff\xff\x00\x00"  # snap length
    b"\x01\x00\x00\x00"  # link type (Ethernet)
)

_PCAPNG_HEADER = (
    b"\x0a\x0d\x0d\x0a"  # Section Header Block type
    b"\x1c\x00\x00\x00"  # block total length = 28
    b"\x4d\x3c\x2b\x1a"  # byte order magic
    b"\x01\x00\x00\x00"  # major/minor version
    b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length (undefined)
    b"\x1c\x00\x00\x00"  # block total length (repeated)
)


def _upload(client, data, filename, content_type="application/octet-stream"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(data), filename, content_type)},
        content_type="multipart/form-data",
    )


def test_upload_minimal_pcap_returns_json(client):
    resp = _upload(client, _PCAP_HEADER, "test.pcap")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "nodes" in body
    assert "edges" in body
    assert "stats" in body


def test_upload_minimal_pcapng_returns_json(client):
    resp = _upload(client, _PCAPNG_HEADER, "test.pcapng")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "nodes" in body


# ── Error paths ───────────────────────────────────────────────────────────────

def test_upload_no_file_returns_400(client):
    resp = client.post("/upload", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_upload_bad_extension_returns_400(client):
    resp = _upload(client, b"hello world", "test.txt")
    assert resp.status_code == 400
    body = resp.get_json()
    assert "error" in body
    assert "Unsupported" in body["error"]


def test_upload_wrong_magic_bytes_returns_400(client):
    """A .pcap file whose first 4 bytes are not a valid pcap magic fails validation."""
    resp = _upload(client, b"\x00\x00\x00\x00" + b"\x00" * 20, "fake.pcap")
    assert resp.status_code == 400
    body = resp.get_json()
    assert "error" in body


def test_upload_malformed_pcap_returns_error(client):
    """Garbage bytes that pass magic-check (unlikely) or a truncated pcap."""
    resp = _upload(client, _PCAP_HEADER[:10], "trunc.pcap")
    # Should either succeed with empty results or return an error — no crash.
    assert resp.status_code in (200, 400)
    assert resp.get_json() is not None


def test_upload_empty_file_returns_error(client):
    resp = _upload(client, b"", "empty.pcap")
    assert resp.status_code == 400
    assert "error" in resp.get_json()


# ── File count cap ────────────────────────────────────────────────────────────

def test_upload_too_many_files_returns_400(client):
    # Werkzeug test client accepts a list value per key for multi-file fields
    data = {
        "file": [(io.BytesIO(_PCAP_HEADER), f"test{i}.pcap") for i in range(101)]
    }
    resp = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert "error" in body
    assert "Too many" in body["error"]


def test_upload_max_files_accepted(client):
    data = {
        "file": [(io.BytesIO(_PCAP_HEADER), f"test{i}.pcap") for i in range(100)]
    }
    resp = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert "nodes" in resp.get_json()


# ── Other routes ──────────────────────────────────────────────────────────────

def test_gpu_status_returns_json(client):
    resp = client.get("/gpu-status")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "gpu" in body


def test_session_schema_returns_ok(client):
    resp = client.get("/session-schema")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body.get("status") == "ok"


def test_index_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"<!DOCTYPE html>" in resp.data or b"<!doctype html" in resp.data.lower()
