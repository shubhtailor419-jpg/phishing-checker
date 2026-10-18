import pytest

from app import create_app


@pytest.fixture()
def client():
    return create_app({"TESTING": True}).test_client()


def post(client, payload):
    return client.post("/api/analyze", json=payload)


def test_pages_load(client):
    for path in ("/", "/learn"):
        response = client.get(path)
        assert response.status_code == 200
        assert b"Phishing" in response.data


def test_learn_page_lists_the_rules(client):
    html = client.get("/learn").data.decode()
    assert "IP address instead of a domain" in html
    assert "Pressure and urgency" in html


def test_health(client):
    assert client.get("/api/health").get_json() == {"status": "ok"}


def test_analyze_url(client):
    response = post(client, {"type": "url", "content": "http://paypa1-secure-login.xyz/verify"})
    body = response.get_json()
    assert response.status_code == 200
    assert body["level"] == "high"
    assert body["score"] >= 51
    assert body["findings"] and body["findings"][0]["points"] >= body["findings"][-1]["points"]


def test_analyze_email(client):
    response = post(client, {"type": "email", "content": "URGENT: send your OTP now"})
    assert response.status_code == 200
    assert response.get_json()["kind"] == "email"


@pytest.mark.parametrize("payload", [
    {"type": "other", "content": "x"},
    {"type": "url"},
    {"type": "url", "content": "   "},
    {"type": "url", "content": 123},
    {"type": "url", "content": "a" * 2049},
    {"type": "email", "content": "a" * 5001},
])
def test_bad_input_is_rejected(client, payload):
    response = post(client, payload)
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_non_json_body_is_rejected(client):
    response = client.post("/api/analyze", data="hello", content_type="text/plain")
    assert response.status_code == 400


def test_oversized_request_is_rejected(client):
    response = client.post("/api/analyze", data="x" * 40000, content_type="application/json")
    assert response.status_code == 413


def test_security_headers_present(client):
    headers = client.get("/").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_api_responses_are_not_cached(client):
    response = post(client, {"type": "url", "content": "example.com"})
    assert response.headers["Cache-Control"] == "no-store"


def test_rate_limit_returns_429():
    limited = create_app({"TESTING": True, "RATE_LIMIT": 2}).test_client()
    codes = [post(limited, {"type": "url", "content": "example.com"}).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]


def test_page_has_no_inline_scripts_or_styles(client):
    html = client.get("/").data.decode().lower()
    assert "<style" not in html
    assert " style=" not in html
    assert "onclick=" not in html
    assert "<script>" not in html
