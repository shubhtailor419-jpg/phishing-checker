import os
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request

from checker import analyze_email, analyze_url
from checker.models import LOW_MAX, MEDIUM_MAX
from checker.rules import RULES

MAX_URL_LEN = 2048
MAX_EMAIL_LEN = 5000
RATE_LIMIT = 30
RATE_WINDOW = 60

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=32 * 1024, RATE_LIMIT=RATE_LIMIT)
    if test_config:
        app.config.update(test_config)

    if os.environ.get("TRUST_PROXY") == "1":
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

    hits = defaultdict(deque)

    def rate_limited(client: str) -> bool:
        now = time.monotonic()
        if len(hits) > 10000:
            hits.clear()
        window = hits[client]
        while window and now - window[0] > RATE_WINDOW:
            window.popleft()
        if len(window) >= app.config["RATE_LIMIT"]:
            return True
        window.append(now)
        return False

    @app.get("/")
    def index():
        return render_template("index.html", max_url=MAX_URL_LEN, max_email=MAX_EMAIL_LEN)

    @app.get("/learn")
    def learn():
        return render_template(
            "learn.html",
            url_rules=[r for r in RULES if r["kind"] == "url"],
            email_rules=[r for r in RULES if r["kind"] == "email"],
            low_max=LOW_MAX,
            medium_max=MEDIUM_MAX,
        )

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.post("/api/analyze")
    def analyze():
        if rate_limited(request.remote_addr or "unknown"):
            return jsonify(error="Too many requests. Please wait a minute and try again."), 429

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="Send a JSON body like {\"type\": \"url\", \"content\": \"...\"}."), 400

        kind = data.get("type")
        content = data.get("content")
        if kind not in ("url", "email"):
            return jsonify(error="'type' must be 'url' or 'email'."), 400
        if not isinstance(content, str) or not content.strip():
            return jsonify(error="Please paste something to check."), 400

        limit = MAX_URL_LEN if kind == "url" else MAX_EMAIL_LEN
        if len(content) > limit:
            return jsonify(error=f"That is too long. The limit is {limit} characters."), 400

        result = analyze_url(content) if kind == "url" else analyze_email(content)
        return jsonify(result.to_dict())

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="That request is too large."), 413

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
