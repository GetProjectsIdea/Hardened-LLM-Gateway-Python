"""The hardened gateway (Flask app factory).

Request pipeline for every call:

1. IP lock-out check (too many failed authentications -> 429)
2. Only allow-listed routes are served; everything else (Ollama /api/pull,
   /api/create, LiteLLM /key/*, /guardrails/*, /config ...) returns 404 and is
   written to the audit log as ``blocked_path``
3. API key from ``Authorization: Bearer`` or ``x-api-key`` (never from the URL),
   verified against the HMAC hash in the key store
4. Per-key rate limit (requests/minute) and daily token budget
5. Body size limit, JSON validation, per-key model allow-list, max_tokens cap
6. Forward to the upstream with the gateway's own upstream key
7. One audit line per request (no API keys, no prompt text)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

from flask import (Flask, Response, abort, jsonify, redirect, render_template, request, session,
                   url_for)

from . import __version__
from .audit import AuditLog, detect, read_events, summary
from .auditor import audit_text
from .keys import KeyError_, KeyStore
from .ratelimit import IpFailureTracker, RateLimiter, TokenBudget
from .settings import Settings, preflight
from .upstream import HTTPUpstream, UpstreamError

PKG = Path(__file__).resolve().parent
ALLOWED_ROUTES = {("GET", "/v1/models"), ("POST", "/v1/chat/completions"), ("POST", "/v1/embeddings")}


def _err(status: int, message: str, code: str, **extra):
    r = jsonify({"error": {"message": message, "type": code, **extra}})
    r.status_code = status
    return r


def create_app(settings: Settings, *, upstream=None, keystore: KeyStore | None = None,
               audit: AuditLog | None = None, limiter: RateLimiter | None = None,
               budget: TokenBudget | None = None, ip_tracker: IpFailureTracker | None = None) -> Flask:
    app = Flask(__name__, template_folder=str(PKG / "templates"), static_folder=str(PKG / "static"))
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_kb * 1024
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_NAME="lgw_admin", PERMANENT_SESSION_LIFETIME=3600)
    if settings.admin_token:
        app.secret_key = hmac.new(settings.admin_token.encode(), b"lgw-session", hashlib.sha256).hexdigest()
    else:
        app.secret_key = secrets.token_hex(32)

    ks = keystore if keystore is not None else KeyStore(settings.keys_file, settings.key_pepper)
    log = audit if audit is not None else AuditLog(settings.audit_log)
    up = upstream if upstream is not None else HTTPUpstream(settings.upstream_url, settings.upstream_api_key, settings.upstream_timeout)
    rl = limiter if limiter is not None else RateLimiter()
    tb = budget if budget is not None else TokenBudget()
    ipt = ip_tracker if ip_tracker is not None else IpFailureTracker(max_failures=settings.auth_fail_limit)
    app.extensions["lgw"] = {"keys": ks, "audit": log, "upstream": up, "settings": settings,
                             "limiter": rl, "budget": tb, "ip": ipt}

    def client_ip() -> str:
        if settings.trust_proxy and request.headers.get("X-Forwarded-For"):
            return request.headers["X-Forwarded-For"].split(",")[0].strip()[:64]
        return request.remote_addr or "?"

    def presented_key() -> str | None:
        h = request.headers.get("Authorization", "")
        if h.lower().startswith("bearer "):
            return h[7:].strip()
        return request.headers.get("x-api-key")

    def authenticate():
        ip = client_ip()
        if ipt.blocked(ip):
            log.write("ip_blocked", ip=ip, path=request.path)
            return None, _err(429, "too many failed authentications, try later", "ip_blocked")
        if any(k in request.args for k in ("key", "api_key", "token")):
            log.write("key_in_url", ip=ip, path=request.path)
            return None, _err(400, "send the API key in the Authorization header, never in the URL", "key_in_url")
        rec, reason = ks.verify(presented_key())
        if reason != "ok":
            ipt.fail(ip)
            log.write("auth_failed", ip=ip, path=request.path, reason=reason,
                      key_id=rec.key_id if rec else None)
            return None, _err(401, "invalid or missing API key", "invalid_api_key")
        ipt.success(ip)
        return rec, None

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        if request.path.startswith("/admin") or request.path == "/":
            resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                       "form-action 'self'; frame-ancestors 'none'")
        return resp

    @app.errorhandler(413)
    def too_big(_e):
        log.write("body_too_large", ip=client_ip(), path=request.path)
        return _err(413, f"request body larger than {settings.max_body_kb} KB", "body_too_large")

    @app.errorhandler(404)
    def not_found(_e):
        if not request.path.startswith(("/admin", "/static")):
            log.write("blocked_path", ip=client_ip(), method=request.method, path=request.path[:200])
        return _err(404, "not found", "not_found")

    @app.errorhandler(405)
    def bad_method(_e):
        log.write("blocked_path", ip=client_ip(), method=request.method, path=request.path[:200])
        return _err(404, "not found", "not_found")

    @app.get("/favicon.ico")
    def favicon():
        return Response(status=204)

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    @app.get("/")
    def index():
        return render_template("index.html", version=__version__, admin=bool(settings.admin_token))

    def allowed_models(rec) -> list[str]:
        return [m for m in settings.models if not rec.models or m in rec.models]

    @app.get("/v1/models")
    def models():
        rec, err = authenticate()
        if err:
            return err
        ms = allowed_models(rec)
        log.write("models", ip=client_ip(), key_id=rec.key_id, user=rec.user, status=200)
        return jsonify({"object": "list", "data": [{"id": m, "object": "model", "owned_by": "gateway"} for m in ms]})

    def proxied(kind: str):
        t0 = time.monotonic()
        rec, err = authenticate()
        if err:
            return err
        ip = client_ip()
        base = {"ip": ip, "key_id": rec.key_id, "user": rec.user, "path": request.path}
        ok, retry = rl.allow(rec.key_id, rec.rpm)
        if not ok:
            log.write("rate_limited", **base, retry_after=retry)
            r = _err(429, f"rate limit of {rec.rpm} requests/minute exceeded", "rate_limited")
            r.headers["Retry-After"] = str(max(1, int(retry + 0.999)))
            return r
        if tb.remaining(rec.key_id, rec.daily_tokens) <= 0:
            log.write("budget_exceeded", **base, daily_tokens=rec.daily_tokens)
            return _err(429, "daily token budget used up", "budget_exceeded")
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            log.write("bad_request", **base, reason="body is not a JSON object")
            return _err(400, "body must be a JSON object", "bad_request")
        model = payload.get("model")
        if not isinstance(model, str) or model not in allowed_models(rec):
            log.write("model_denied", **base, model=str(model)[:80])
            return _err(403, f"model {model!r} is not allowed for this key", "model_denied",
                        allowed=allowed_models(rec))
        stream = False
        if kind == "chat":
            msgs = payload.get("messages")
            if not isinstance(msgs, list) or not msgs or not all(isinstance(m, dict) for m in msgs):
                log.write("bad_request", **base, model=model, reason="messages must be a non-empty list")
                return _err(400, "messages must be a non-empty list of objects", "bad_request")
            mt = payload.get("max_tokens")
            if mt is not None and (not isinstance(mt, int) or isinstance(mt, bool) or mt < 1):
                log.write("bad_request", **base, model=model, reason="invalid max_tokens")
                return _err(400, "max_tokens must be a positive integer", "bad_request")
            payload["max_tokens"] = min(mt or settings.max_tokens, settings.max_tokens)
            stream = bool(payload.get("stream"))
            payload["stream"] = False  # gateway counts tokens on complete responses
            payload.pop("user", None)
            payload["user"] = rec.user
        extra = {}
        if settings.log_prompt_hash:
            raw = json.dumps(payload.get("messages") or payload.get("input") or "", sort_keys=True)
            extra = {"prompt_sha256": hashlib.sha256(raw.encode()).hexdigest()[:16], "prompt_chars": len(raw)}
        try:
            status, data = up.chat(payload) if kind == "chat" else up.embeddings(payload)
        except UpstreamError as e:
            log.write("upstream_error", **base, model=model, status=502, error=str(e)[:200],
                      max_tokens=payload.get("max_tokens"))
            return _err(502, "upstream model server unavailable", "upstream_error")
        usage = (data or {}).get("usage") or {}
        total = int(usage.get("total_tokens") or 0)
        tb.add(rec.key_id, total)
        log.write("request", **base, model=model, status=status, max_tokens=payload.get("max_tokens"),
                  prompt_tokens=usage.get("prompt_tokens"), completion_tokens=usage.get("completion_tokens"),
                  total_tokens=total, latency_ms=int((time.monotonic() - t0) * 1000), stream=stream, **extra)
        if status >= 400:
            return _err(502 if status >= 500 else status, "upstream returned an error", "upstream_error",
                        upstream_status=status)
        if stream and kind == "chat":
            chunk = {"id": data.get("id", "chatcmpl-gw"), "object": "chat.completion.chunk", "model": model,
                     "choices": [{"index": 0, "delta": {"role": "assistant",
                                                       "content": data["choices"][0]["message"]["content"]},
                                  "finish_reason": "stop"}]}
            body = f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"
            return Response(body, mimetype="text/event-stream")
        resp = jsonify(data)
        resp.headers["X-Gateway-Tokens-Remaining"] = str(tb.remaining(rec.key_id, rec.daily_tokens))
        return resp

    @app.post("/v1/chat/completions")
    def chat():
        return proxied("chat")

    @app.post("/v1/embeddings")
    def embeddings():
        return proxied("embeddings")

    # ------------------------------------------------------------- admin UI
    def admin_enabled():
        if not settings.admin_token:
            abort(404)

    def require_admin():
        admin_enabled()
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return None

    def check_csrf():
        tok = session.get("csrf")
        if not tok or not hmac.compare_digest(tok, request.form.get("csrf", "")):
            abort(400)

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        admin_enabled()
        error = None
        if request.method == "POST":
            ip = client_ip()
            if ipt.blocked(ip):
                log.write("ip_blocked", ip=ip, path=request.path)
                return _err(429, "too many failed logins, try later", "ip_blocked")
            if hmac.compare_digest(request.form.get("token", "").encode(), settings.admin_token.encode()):
                session.clear()
                session["admin"] = True
                session["csrf"] = secrets.token_urlsafe(24)
                ipt.success(ip)
                log.write("admin_login", ip=ip)
                return redirect(url_for("admin"))
            ipt.fail(ip)
            log.write("admin_login_failed", ip=ip)
            error = "Wrong admin token."
        return render_template("login.html", error=error, version=__version__)

    @app.post("/admin/logout")
    def admin_logout():
        admin_enabled()
        check_csrf()
        session.clear()
        return redirect(url_for("admin_login"))

    @app.get("/admin")
    def admin():
        r = require_admin()
        if r:
            return r
        events = read_events(settings.audit_log)
        budgets = {k.key_id: k.daily_tokens for k in ks.list()}
        new_key = session.pop("new_key", None)
        return render_template("admin.html", checks=preflight(settings), keys=ks.list(), new_key=new_key,
                               events=list(reversed(events[-25:])), findings=detect(events, budgets=budgets),
                               stats=summary(events), csrf=session["csrf"], settings=settings,
                               budget=tb, flash=session.pop("flash", None), version=__version__)

    @app.post("/admin/keys")
    def admin_keys():
        r = require_admin()
        if r:
            return r
        check_csrf()
        action = request.form.get("action")
        try:
            if action == "create":
                models = [m.strip() for m in request.form.get("models", "").split(",") if m.strip()]
                full, rec = ks.create(request.form.get("user", ""), models=models,
                                      rpm=int(request.form.get("rpm") or 30),
                                      daily_tokens=int(request.form.get("daily_tokens") or 200000),
                                      ttl_days=float(request.form.get("ttl_days") or 90))
                session["new_key"] = {"user": rec.user, "key": full}
                log.write("key_created", ip=client_ip(), key_id=rec.key_id, user=rec.user, by="admin-ui")
            elif action in ("revoke", "rotate"):
                kid = request.form.get("key_id", "")
                if action == "revoke":
                    rec = ks.revoke(kid)
                else:
                    full, rec = ks.rotate(kid)
                    session["new_key"] = {"user": rec.user, "key": full}
                log.write(f"key_{action}d", ip=client_ip(), key_id=kid, user=rec.user, by="admin-ui")
            else:
                abort(400)
        except (KeyError_, ValueError) as e:
            session["flash"] = str(e)
        return redirect(url_for("admin"))

    @app.route("/admin/audit-config", methods=["GET", "POST"])
    def admin_audit_config():
        r = require_admin()
        if r:
            return r
        findings, text, name = None, "", "docker-compose.yml"
        if request.method == "POST":
            check_csrf()
            text = request.form.get("text", "")[:200_000]
            name = request.form.get("name", "docker-compose.yml")
            findings = audit_text(text, name)
        return render_template("audit_config.html", findings=findings, text=text, name=name,
                               csrf=session["csrf"], version=__version__)

    @app.template_filter("ts")
    def ts(v):
        return time.strftime("%Y-%m-%d %H:%M", time.gmtime(v)) + " UTC" if v else "never"

    return app
