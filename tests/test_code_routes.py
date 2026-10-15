"""Code-review routes: CSRF, paste flow, upload flow, and safe error states."""

from __future__ import annotations

import re
import pytest

from app.services.code_analyzer import CodeReviewError

PHP_SAMPLE = "<?php\n$id = $_GET['id'];\nmysqli_query($conn, \"SELECT * FROM users WHERE id = \" . $id);\n"


def _csrf_post(client, url, data, files=None):
    client.get("/")  # obtain the CSRF cookie
    token = client.cookies.get("phantom_csrf")
    data = dict(data)
    data["csrf_token"] = token
    return client.post(url, data=data, files=files)


def test_form_renders_with_privacy_notice(app_client):
    response = app_client.get("/code-review")
    assert response.status_code == 200
    assert "Privacy notice" in response.text
    assert "never executed" in response.text.lower()
    assert 'name="csrf_token"' in response.text


def test_paste_review_renders_findings(app_client):
    response = _csrf_post(
        app_client,
        "/code-review",
        {"code": PHP_SAMPLE, "language": "php"},
    )
    assert response.status_code == 200
    body = response.text
    assert "Review results for" in body
    assert "pasted snippet" in body
    assert "SQL query built with variables" in body
    assert "Line 3" in body
    assert "deterministic rule" in body
    assert "prepared statements" in body
    assert "Nothing was executed" in body


def test_paste_requires_csrf(app_client):
    response = app_client.post("/code-review", data={"code": PHP_SAMPLE, "language": "php"})
    assert response.status_code == 403


def test_malicious_code_content_is_escaped_in_results(app_client):
    xss_line = "<?php\necho $_GET['x']; // <script>alert(1)</script>\n"
    response = _csrf_post(
        app_client,
        "/code-review",
        {"code": xss_line, "language": "php"},
    )
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_invalid_submission_shows_safe_error(app_client):
    response = _csrf_post(
        app_client,
        "/code-review",
        {"code": "", "language": "php"},
    )
    assert response.status_code == 400
    assert "Review not completed." in response.text


def test_undetectable_language_shows_guidance(app_client):
    response = _csrf_post(
        app_client,
        "/code-review",
        {"code": "????", "language": "auto"},
    )
    assert response.status_code == 400
    assert "Could not detect" in response.text


def test_unexpected_failure_is_generic(app_client, monkeypatch):
    def explode(content, language_choice):
        raise RuntimeError("boom internal detail")

    monkeypatch.setattr("app.routes.code_review.analyze_code", explode)
    response = _csrf_post(
        app_client,
        "/code-review",
        {"code": "x = 1", "language": "python"},
    )
    assert response.status_code == 502
    assert "boom" not in response.text


def test_upload_review_from_extension(app_client):
    response = _csrf_post(
        app_client,
        "/code-review/upload",
        {"language": "auto"},
        files={"file": ("vulnerable.php", PHP_SAMPLE.encode(), "application/x-php")},
    )
    assert response.status_code == 200
    assert "vulnerable.php" in response.text
    assert "SQL query built with variables" in response.text


def test_upload_rejects_unknown_extension(app_client):
    response = _csrf_post(
        app_client,
        "/code-review/upload",
        {"language": "auto"},
        files={"file": ("notes.txt", b"SELECT * FROM x", "text/plain")},
    )
    assert response.status_code == 400
    assert "Unsupported file type" in response.text
    assert ".php" in response.text  # lists supported extensions


def test_upload_rejects_oversized_file(app_client):
    big = b"x = 1\n" * 100_000  # ~600 KiB > 512 KiB limit
    response = _csrf_post(
        app_client,
        "/code-review/upload",
        {"language": "auto"},
        files={"file": ("big.py", big, "text/x-python")},
    )
    assert response.status_code == 400
    assert "too large" in response.text


def test_upload_rejects_binary_file(app_client):
    response = _csrf_post(
        app_client,
        "/code-review/upload",
        {"language": "auto"},
        files={"file": ("blob.php", b"\x00\x01\x02\x03binary", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "UTF-8" in response.text or "binary" in response.text.lower()


def test_upload_without_file_shows_error(app_client):
    response = _csrf_post(app_client, "/code-review/upload", {"language": "auto"})
    assert response.status_code == 400
    assert "Choose a file" in response.text


def test_upload_requires_csrf(app_client):
    response = app_client.post(
        "/code-review/upload",
        files={"file": ("a.php", PHP_SAMPLE.encode(), "application/x-php")},
    )
    assert response.status_code == 403


def test_upload_filename_is_sanitized_in_results(app_client):
    response = _csrf_post(
        app_client,
        "/code-review/upload",
        {"language": "auto"},
        files={"file": ("../../etc/passwd.php", PHP_SAMPLE.encode(), "application/x-php")},
    )
    assert response.status_code == 200
    assert "../../etc" not in response.text
    assert "passwd.php" in response.text


def test_secrets_are_masked_in_rendered_results(app_client):
    content = "API_KEY = 'sk-live-abcdef123456'\n"
    response = _csrf_post(
        app_client,
        "/code-review",
        {"code": content, "language": "python"},
    )
    assert response.status_code == 200
    assert "[REDACTED]" in response.text
    # The secret must not appear in any evidence block (the paste textarea
    # echoes the user's own input back, which is fine).
    evidence_blocks = re.findall(
        r'<pre class="code-evidence[^"]*"><code>(.*?)</code></pre>',
        response.text,
        flags=re.DOTALL,
    )
    assert evidence_blocks
    assert all("sk-live-abcdef123456" not in block for block in evidence_blocks)
