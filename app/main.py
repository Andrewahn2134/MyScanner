# Copyright (c) 2025 AndrewAhn
# SPDX-License-Identifier: MIT


from __future__ import annotations
import os, base64, io, uuid, json
from datetime import datetime, timedelta, date, time
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_, cast, String, update
from sqlalchemy.exc import OperationalError
import qrcode

from app.db import engine, get_db, Base, SessionLocal
from app import models, crud
from app.exporter import make_xlsx_bytes
from app.security import hash_password, verify_password, COOKIE_NAME, PREAUTH_COOKIE, new_totp_secret, totp_uri, verify_totp, validate_password_complexity, generate_temp_password
from app.utils import to_kst, parse_targets, validate_ports, parse_allowed_targets, target_allowed, sanitize_extra_args
from app import nmap_runner

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

ALLOWED_TARGETS = parse_allowed_targets(os.environ.get("ALLOWED_TARGETS", ""))
KST = ZoneInfo("Asia/Seoul")
UTC = ZoneInfo("UTC")


def kst_date_to_utc_start(date_str: str) -> datetime:
    """Convert a YYYY-MM-DD (KST) date string to a naive UTC datetime at KST 00:00."""
    d = date.fromisoformat(date_str)
    return datetime.combine(d, time.min, tzinfo=KST).astimezone(UTC).replace(tzinfo=None)

def kst_date_to_utc_end_exclusive(date_str: str) -> datetime:
    """Convert a YYYY-MM-DD (KST) date string to a naive UTC datetime at next-day KST 00:00."""
    d = date.fromisoformat(date_str) + timedelta(days=1)
    return datetime.combine(d, time.min, tzinfo=KST).astimezone(UTC).replace(tzinfo=None)




def client_ip(req: Request) -> str:
    return req.client.host if req.client else ""

def get_current_user(req: Request, db: Session):
    sid = req.cookies.get(COOKIE_NAME)
    if not sid:
        return None
    s = crud.get_session(db, sid)
    if not s or s.revoked:
        return None
    if s.expires_at < datetime.utcnow():
        return None
    return s.user

def inject_ctx(req: Request, db: Session):
    u = get_current_user(req, db)
    templates.env.globals["current_user"] = u
    templates.env.globals["to_kst"] = to_kst
    return u

def require_admin(u: models.User | None):
    return bool(u and u.role == "admin")


def _migrate():
    # v2.1 lightweight migration (no Alembic)
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "ALTER TABLE IF EXISTS scan_runs ADD COLUMN IF NOT EXISTS scan_name VARCHAR(120);"
        )
        conn.exec_driver_sql(
            "ALTER TABLE IF EXISTS scan_runs ADD COLUMN IF NOT EXISTS executed_command TEXT;"
        )
        conn.exec_driver_sql(
            "ALTER TABLE IF EXISTS port_inventory ADD COLUMN IF NOT EXISTS operator VARCHAR(60);"
        )
        conn.exec_driver_sql(
            "ALTER TABLE IF EXISTS port_inventory ADD COLUMN IF NOT EXISTS owner VARCHAR(60);"
        )
        conn.exec_driver_sql("ALTER TABLE IF EXISTS port_inventory ADD COLUMN IF NOT EXISTS open_misses INTEGER DEFAULT 0;")
        conn.exec_driver_sql("ALTER TABLE IF EXISTS port_inventory ADD COLUMN IF NOT EXISTS inactive BOOLEAN DEFAULT FALSE;")
        conn.exec_driver_sql("ALTER TABLE IF EXISTS port_inventory ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'ACTIVE';")
        conn.exec_driver_sql("ALTER TABLE IF EXISTS port_inventory ADD COLUMN IF NOT EXISTS ticket VARCHAR(1024);")
        conn.exec_driver_sql("ALTER TABLE IF EXISTS port_inventory ALTER COLUMN ticket TYPE VARCHAR(1024);")
        conn.exec_driver_sql("ALTER TABLE IF EXISTS port_inventory ADD COLUMN IF NOT EXISTS remediation_at TIMESTAMP;")
        conn.exec_driver_sql("ALTER TABLE IF EXISTS port_inventory ADD COLUMN IF NOT EXISTS remediation_note TEXT;")
        # user security policy
        conn.exec_driver_sql("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;")
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS run_open_ports ("
            "run_id INTEGER NOT NULL REFERENCES scan_runs(id), "
            "ip VARCHAR(64) NOT NULL, "
            "port INTEGER NOT NULL, "
            "firewall_blocked VARCHAR(1) NOT NULL DEFAULT 'N', "
            "PRIMARY KEY (run_id, ip, port, firewall_blocked)"
            ");"
        )

        # scan_run_port_scopes / ranges / hosts for auditable port-scope coverage & safe miss accounting
        conn.exec_driver_sql("ALTER TABLE IF EXISTS scan_runs ADD COLUMN IF NOT EXISTS scan_type VARCHAR(10) DEFAULT 'tcp';")
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS scan_run_port_scopes ("
            "id SERIAL PRIMARY KEY, "
            "run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE, "
            "proto VARCHAR(8) NOT NULL DEFAULT 'tcp', "
            "scope_kind VARCHAR(20) NOT NULL DEFAULT 'explicit', "
            "raw_spec TEXT, "
            "top_ports INTEGER, "
            "CONSTRAINT uq_run_proto_scope UNIQUE (run_id, proto)"
            ");"
        )
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS scan_run_port_ranges ("
            "id SERIAL PRIMARY KEY, "
            "scope_id INTEGER NOT NULL REFERENCES scan_run_port_scopes(id) ON DELETE CASCADE, "
            "port_start INTEGER NOT NULL, "
            "port_end INTEGER NOT NULL"
            ");"
        )
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS scan_run_hosts ("
            "id SERIAL PRIMARY KEY, "
            "run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE, "
            "ip VARCHAR(64) NOT NULL, "
            "is_up BOOLEAN NOT NULL DEFAULT TRUE, "
            "CONSTRAINT uq_run_ip UNIQUE (run_id, ip)"
            ");"
        )


@app.on_event("startup")
def _startup():
    last = None
    for _ in range(40):
        try:
            Base.metadata.create_all(bind=engine)
            _migrate()
            return
        except OperationalError as e:
            last = e
            import time
            time.sleep(1)
    raise last


@app.middleware("http")
async def _force_pw_change(request: Request, call_next):
    """If a user is flagged for password change, force them to /change_password."""
    path = request.url.path
    # allow auth-related endpoints and static assets
    if path in ("/login", "/signup", "/logout", "/mfa/enroll", "/change_password") or path.startswith("/static"):
        return await call_next(request)
    sid = request.cookies.get(COOKIE_NAME)
    if sid:
        db = SessionLocal()
        try:
            s = crud.get_session(db, sid)
            if s and (not s.revoked) and s.expires_at >= datetime.utcnow():
                user = s.user
                if getattr(user, "must_change_password", False):
                    return RedirectResponse("/change_password", status_code=302)
        finally:
            db.close()
    return await call_next(request)

@app.get("/", response_class=HTMLResponse)
def dashboard(req: Request, fw: str | None = None, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    fw_val = fw if fw in ("Y", "N") else ""
    runs = crud.list_scan_runs(db, limit=30)

    # If a RUNNING scan has finished (nmap process exited), mark it as DONE so
    # the UI can show the Ingest button.
    updated_any = False
    now = datetime.utcnow()
    for r in runs:
        try:
            if r.status == "RUNNING" and nmap_runner.scan_finished(r.xml_id):
                r.status = "DONE"
                r.finished_at = r.finished_at or now
                updated_any = True
        except Exception:
            pass
    if updated_any:
        try:
            db.commit()
        except Exception:
            db.rollback()

    # Total Ports (Opened): ports currently tracked for action (ACTIVE/DENIED only)
    total_opened = crud.count_total_active_open_ports(db, fw_val if fw_val else None)

    # Open Ports (latest): based on the most recent SUCCESS scan (respecting scan deletion)
    last_run = crud.latest_finished_run(db, fw_val if fw_val else None)
    open_latest = crud.count_run_open_ports(db, last_run.id) if last_run else 0

    triage_q = (
        select(func.count())
        .select_from(models.PortInventory)
        .where(models.PortInventory.state_latest == "open")
        .where(models.PortInventory.inactive == False)
        .where(models.PortInventory.status.in_(("ACTIVE","DENIED")))
        .where(
            (models.PortInventory.status == "DENIED")
            | (
                (models.PortInventory.status == "ACTIVE")
                & (
                    (models.PortInventory.reviewed == False)
                    | (models.PortInventory.hostname.is_(None))
                    | (models.PortInventory.operator.is_(None))
                    | (models.PortInventory.owner.is_(None))
                    | (models.PortInventory.ticket.is_(None))
                    | (models.PortInventory.comment.is_(None))
                )
            )
        )
    )
    if fw_val:
        triage_q = triage_q.where(models.PortInventory.firewall_blocked == fw_val)
    triage_cnt = db.execute(triage_q).scalar_one()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": req,
            "user": u,
            "fw": fw_val,
            "runs": runs,
            "metrics": {"total_opened": total_opened, "open_latest": open_latest, "triage": triage_cnt},
        },
    )

@app.get("/signup", response_class=HTMLResponse)

def signup_form(req: Request, db: Session = Depends(get_db)):
    inject_ctx(req, db)
    return templates.TemplateResponse("signup.html", {"request": req, "error": None})

@app.post("/signup")
def signup(req: Request, db: Session = Depends(get_db),
           user_id: str = Form(...), password: str = Form(...),
           username: str = Form(...), email: str = Form(...),
           department: str = Form(...), phone_number: str = Form(...)):
    inject_ctx(req, db)
    uid = user_id.strip()
    pw_err = validate_password_complexity(password)
    if pw_err:
        return templates.TemplateResponse("signup.html", {"request": req, "error": pw_err}, status_code=400)

    if crud.get_user_by_user_id(db, uid):
        return templates.TemplateResponse("signup.html", {"request": req, "error": "UserId already exists"}, status_code=400)

    u = models.User(
        user_id=uid,
        password_hash=hash_password(password),
        username=username.strip(),
        email=email.strip(),
        department=department.strip(),
        phone_number=phone_number.strip(),
        role="operator",
        mfa_enabled=False,
        totp_secret=None,
    )
    db.add(u)
    db.commit()
    crud.add_audit(db, None, "SIGNUP", "user", uid, None, {"user_id": uid}, client_ip(req))
    return RedirectResponse("/login?msg=signup_ok", status_code=302)

@app.get("/login", response_class=HTMLResponse)
def login_form(req: Request, msg: str | None = None, db: Session = Depends(get_db)):
    inject_ctx(req, db)
    friendly = "가입 성공! 로그인하면 최초 1회 MFA 등록을 진행하세요." if msg == "signup_ok" else None
    return templates.TemplateResponse("login.html", {"request": req, "error": None, "msg": friendly})

@app.post("/login", response_class=HTMLResponse)
def login(req: Request, db: Session = Depends(get_db),
          user_id: str = Form(...), password: str = Form(...), mfa_code: str = Form(None)):
    inject_ctx(req, db)
    u = crud.get_user_by_user_id(db, user_id.strip())
    if not u or not verify_password(password, u.password_hash):
        return templates.TemplateResponse("login.html", {"request": req, "error": "Invalid credentials", "msg": None}, status_code=401)

    if not u.mfa_enabled:
        token = crud.create_preauth(db, u, ttl_minutes=10)
        crud.add_audit(db, u.id, "LOGIN_PREAUTH", "user", u.user_id, None, "mfa_enroll_required", client_ip(req))
        resp = RedirectResponse("/mfa/enroll", status_code=302)
        resp.set_cookie(PREAUTH_COOKIE, token, httponly=True, samesite="lax")
        return resp

    if not u.totp_secret:
        return templates.TemplateResponse("login.html", {"request": req, "error": "MFA secret missing. Contact admin.", "msg": None}, status_code=500)

    code = (mfa_code or "").strip()
    if not code or not verify_totp(u.totp_secret, code):
        return templates.TemplateResponse("login.html", {"request": req, "error": "MFA failed", "msg": None}, status_code=401)

    sid, _ = crud.create_session(db, u)
    crud.add_audit(db, u.id, "LOGIN", "user", u.user_id, None, "ok", client_ip(req))
    dest = "/change_password" if getattr(u, "must_change_password", False) else "/"
    resp = RedirectResponse(dest, status_code=302)
    resp.set_cookie(COOKIE_NAME, sid, httponly=True, samesite="lax")
    return resp

@app.get("/logout")
def logout(req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    sid = req.cookies.get(COOKIE_NAME)
    if sid:
        crud.revoke_session(db, sid)
        if u:
            crud.add_audit(db, u.id, "LOGOUT", "user", u.user_id, None, "ok", client_ip(req))
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    return resp

@app.get("/change_password", response_class=HTMLResponse)
def change_password_form(req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("change_password.html", {"request": req, "error": None})

@app.post("/change_password", response_class=HTMLResponse)
def change_password(req: Request, db: Session = Depends(get_db), current_password: str = Form(...), new_password: str = Form(...), new_password_confirm: str = Form(...)):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)
    # verify current password
    if not verify_password(current_password, u.password_hash):
        return templates.TemplateResponse("change_password.html", {"request": req, "error": "현재 비밀번호가 올바르지 않아."}, status_code=400)
    if new_password != new_password_confirm:
        return templates.TemplateResponse("change_password.html", {"request": req, "error": "새 비밀번호 확인이 일치하지 않아."}, status_code=400)
    err = validate_password_complexity(new_password)
    if err:
        return templates.TemplateResponse("change_password.html", {"request": req, "error": err}, status_code=400)
    # update password & clear flag
    u.password_hash = hash_password(new_password)
    u.must_change_password = False
    db.commit()
    # revoke all existing sessions and issue a new one
    sessions = db.execute(select(models.Session).where(models.Session.user_id == u.id, models.Session.revoked == False)).scalars().all()
    for s in sessions:
        s.revoked = True
    db.commit()
    new_sid, _ = crud.create_session(db, u)
    crud.add_audit(db, u.id, "USER_CHANGE_PASSWORD", "user", u.user_id, None, "ok", client_ip(req))
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(COOKIE_NAME, new_sid, httponly=True, samesite="lax")
    return resp

@app.get("/mfa/enroll", response_class=HTMLResponse)
def mfa_enroll(req: Request, db: Session = Depends(get_db)):
    inject_ctx(req, db)
    token = req.cookies.get(PREAUTH_COOKIE)
    pa = crud.get_preauth(db, token)
    if not pa or pa.expires_at < datetime.utcnow():
        if token:
            crud.delete_preauth(db, token)
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(PREAUTH_COOKIE)
        return resp

    user = crud.get_user(db, pa.user_id)
    if not user:
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(PREAUTH_COOKIE)
        return resp

    if user.mfa_enabled:
        crud.delete_preauth(db, token)
        resp = RedirectResponse("/", status_code=302)
        resp.delete_cookie(PREAUTH_COOKIE)
        return resp

    if not user.totp_secret:
        user.totp_secret = new_totp_secret()
        db.commit()

    uri = totp_uri(user.user_id, user.totp_secret, issuer="MyScanner")
    qr = qrcode.QRCode(border=2, box_size=6)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    return templates.TemplateResponse("mfa_enroll.html", {"request": req, "user": user, "secret": user.totp_secret, "qr_png_base64": qr_b64, "error": None})

@app.post("/mfa/enroll", response_class=HTMLResponse)
def mfa_enroll_post(req: Request, db: Session = Depends(get_db), code: str = Form(...)):
    inject_ctx(req, db)
    token = req.cookies.get(PREAUTH_COOKIE)
    pa = crud.get_preauth(db, token)
    if not pa or pa.expires_at < datetime.utcnow():
        if token:
            crud.delete_preauth(db, token)
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(PREAUTH_COOKIE)
        return resp

    user = crud.get_user(db, pa.user_id)
    if not user or not user.totp_secret:
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(PREAUTH_COOKIE)
        return resp

    if not verify_totp(user.totp_secret, code.strip()):
        # regenerate QR for display
        uri = totp_uri(user.user_id, user.totp_secret, issuer="MyScanner")
        qr = qrcode.QRCode(border=2, box_size=6)
        qr.add_data(uri); qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO(); img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        return templates.TemplateResponse("mfa_enroll.html", {"request": req, "user": user, "secret": user.totp_secret, "qr_png_base64": qr_b64, "error": "Invalid code"}, status_code=400)

    # Persist MFA enabled flag defensively (avoid ORM edge-cases after admin reset)
    db.execute(update(models.User).where(models.User.id == user.id).values(mfa_enabled=True))
    db.commit()
    db.refresh(user)
    crud.add_audit(db, user.id, "MFA_ENABLED", "user", user.user_id, None, "enabled", client_ip(req))

    crud.delete_preauth(db, token)
    sid, _ = crud.create_session(db, user)
    crud.add_audit(db, user.id, "LOGIN", "user", user.user_id, None, "ok", client_ip(req))
    dest = "/change_password" if getattr(user, "must_change_password", False) else "/"
    resp = RedirectResponse(dest, status_code=302)
    resp.delete_cookie(PREAUTH_COOKIE)
    resp.set_cookie(COOKIE_NAME, sid, httponly=True, samesite="lax")
    return resp


@app.get("/results", response_class=HTMLResponse)
def results(
    req: Request,
    start: str | None = None,
    end: str | None = None,
    fw: str | None = None,
    db: Session = Depends(get_db),
):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    fw_val = fw if fw in ("Y", "N") else ""
    rows = []
    err = ""
    if start and end:
        try:
            # inclusive end-date for users; implement [start, end+1day)
            
            # inclusive end-day in KST; convert KST date boundaries to UTC for DB filtering
            start_dt = kst_date_to_utc_start(start)
            end_dt = kst_date_to_utc_end_exclusive(end)
            rows = crud.query_inventory(db, start_dt, end_dt, fw_val if fw_val else None)

        except Exception as e:
            err = str(e)

    return templates.TemplateResponse(
        "results.html",
        {
            "request": req,
            "rows": rows,
            "start": start or "",
            "end": end or "",
            "fw": fw_val,
            "err": err,
        },
    )


@app.get("/triage", response_class=HTMLResponse)
def triage(
    req: Request,
    fw: str | None = None,
    status: str | None = None,
    ip: str | None = None,
    port: str | None = None,
    owner: str | None = None,
    operator: str | None = None,
    comment: str | None = None,
    db: Session = Depends(get_db),
):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    fw_val = fw if fw in ("Y", "N") else ""
    status_val = status if status in ("ACTIVE", "DENIED") else ""
    ip_q = ip.strip() if ip else ""
    port_q = port.strip() if port else ""
    owner_q = owner.strip() if owner else ""
    operator_q = operator.strip() if operator else ""
    comment_q = comment.strip() if comment else ""
    comment_q = comment.strip() if comment else ""
    comment_q = comment.strip() if comment else ""

    rows = crud.query_triage(
        db,
        fw_val if fw_val else None,
        status_val if status_val else None,
        ip_q if ip_q else None,
        port_q if port_q else None,
        owner_q if owner_q else None,
        operator_q if operator_q else None,
        comment_q if comment_q else None,
    )

    # Counters (respect Firewall + all text filters, ignore Status filter so you always see both)
    # Counts reflect the filtered queue
    active_cnt = sum(1 for r in rows if getattr(r, "status", "ACTIVE") == "ACTIVE")
    denied_cnt = sum(1 for r in rows if getattr(r, "status", "ACTIVE") == "DENIED")

    return templates.TemplateResponse(
        "triage.html",
        {
            "request": req,
            "rows": rows,
            "fw": fw_val,
            "status": status_val,
            "ip": ip_q,
            "port": port_q,
            "owner": owner_q,
            "operator": operator_q,
            "comment": comment_q,
            "comment": comment_q,
            "active_cnt": active_cnt,
            "denied_cnt": denied_cnt,
        },
    )
@app.get("/port/{inv_id}", response_class=HTMLResponse)
def port_detail(req: Request, inv_id: int, back: str | None = None, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)
    inv = db.get(models.PortInventory, inv_id)
    if not inv:
        return RedirectResponse("/results", status_code=302)
    events = db.execute(select(models.PortEvent).where(
        and_(models.PortEvent.ip==inv.ip, models.PortEvent.port==inv.port, models.PortEvent.firewall_blocked==inv.firewall_blocked)
    ).order_by(models.PortEvent.event_time.desc()).limit(20)).scalars().all()
    return templates.TemplateResponse("port_detail.html", {"request": req, "user": u, "inv": inv, "events": events, "back": back or "/results"})

@app.post("/port/{inv_id}")
def port_update(req: Request, inv_id: int, db: Session = Depends(get_db),
                hostname: str = Form(None), operator: str = Form(None), owner: str = Form(None),
                status: str = Form(None), ticket: str = Form(None), remediation_note: str = Form(None),
                comment: str = Form(None), reviewed: str = Form("0"), back: str = Form("/results")):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    inv_obj = db.get(models.PortInventory, inv_id)
    if not inv_obj:
        return RedirectResponse("/results", status_code=302)

    # Operators can only edit: hostname/operator/owner/ticket.
    # Admins can edit all fields (status/remediation_note/reviewed/comment).
    if u.role == "operator":
        status = None
        remediation_note = None
        reviewed = "1" if inv_obj.reviewed else "0"

    # If a port is INACTIVE (misses>=2), lock Status/Reviewed to prevent human error.
    if getattr(inv_obj, "inactive", False):
        status = None
        reviewed = "1" if inv_obj.reviewed else "0"

    hn = (hostname or "").strip()
    op = (operator or "").strip()
    ow = (owner or "").strip()
    hn_val = hn if hn else None
    op_val = op if op else None
    ow_val = ow if ow else None
    inv, before, after = crud.update_asset_port(
        db,
        inv_id,
        hn,
        op,
        ow,
        (status or "").strip().upper() or None,
        (ticket or "").strip() or None,
        (remediation_note or "").strip() or None,
        (comment or "").strip() or None,
        reviewed == "1",
    )
    if not inv:
        return RedirectResponse("/results", status_code=302)
    crud.add_audit(db, u.id, "PORT_META_UPDATE", "port", f"{inv.ip}:{inv.port}:{inv.firewall_blocked}", before, after, client_ip(req))
    return RedirectResponse(back or "/results", status_code=302)


@app.get("/remediated", response_class=HTMLResponse)
def remediated(
    req: Request,
    fw: str | None = None,
    status: str | None = None,
    ip: str | None = None,
    port: str | None = None,
    db: Session = Depends(get_db),
):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    fw_val = fw if fw in ("Y","N") else ""
    status_val = status if status in ("REMEDIATED","IGNORED","INACTIVE") else ""
    ip_q = ip.strip() if ip else ""
    port_q = port.strip() if port else ""

    inv = models.PortInventory
    base = select(inv).where((inv.status.in_(("REMEDIATED","IGNORED"))) | (inv.inactive == True))

    if fw_val:
        base = base.where(inv.firewall_blocked == fw_val)

    if status_val == "INACTIVE":
        base = base.where(inv.inactive == True)
    elif status_val in ("REMEDIATED","IGNORED"):
        base = base.where(inv.status == status_val)

    if ip_q:
        base = base.where(inv.ip == ip_q)
    if port_q:
        try:
            base = base.where(inv.port == int(port_q))
        except Exception:
            pass

    rows = db.execute(base.order_by(inv.ip.asc(), inv.port.asc())).scalars().all()

    return templates.TemplateResponse(
        "remediated.html",
        {
            "request": req,
            "rows": rows,
            "fw": fw_val,
            "status": status_val,
            "ip": ip_q,
            "port": port_q,
        },
    )
@app.get("/assets", response_class=HTMLResponse)
def assets(req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)
    assets = crud.list_assets(db)
    return templates.TemplateResponse("assets.html", {"request": req, "assets": assets})

@app.get("/scan/{run_id}", response_class=HTMLResponse)
def scan_view(run_id: int, req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    run = db.get(models.ScanRun, run_id)
    if not run:
        return PlainTextResponse("Not found", status_code=404)

    # If scan finished but status is still RUNNING, flip to DONE so Ingest appears.
    if run.status == "RUNNING":
        try:
            if nmap_runner.scan_finished(run.xml_id):
                run.status = "DONE"
                run.finished_at = run.finished_at or datetime.utcnow()
                db.commit()
        except Exception:
            db.rollback()

    log_tail = ""
    try:
        with open(run.log_path, "r", encoding="utf-8", errors="ignore") as f:
            log_tail = "".join(f.readlines()[-200:])
    except Exception:
        pass

    diff = None
    if run.status == "DONE":
        try:
            diff = crud.compute_run_diff(db, run)
        except Exception:
            diff = None

    return templates.TemplateResponse("scan_view.html", {"request": req, "run": run, "log_tail": log_tail, "diff": diff})


@app.get("/run-scan", response_class=HTMLResponse)
def run_scan_form(req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("run_scan.html", {"request": req, "error": None, "run": None})

@app.post("/run-scan", response_class=HTMLResponse)
def run_scan(
    req: Request,
    db: Session = Depends(get_db),
    scan_name: str = Form(None),
    targets: str = Form(...),
    ports: str = Form(None),
    top_ports: str = Form(None),
    scan_type: str = Form("tcp"),
    fw: str = Form("N"),
    extra: str = Form(None),
):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)

    try:
        tlist = parse_targets(targets)

        fw_val = "Y" if fw == "Y" else "N"
        stype = "udp" if (scan_type or "").lower() == "udp" else "tcp"

        tp = None
        if top_ports:
            tp_s = str(top_ports).strip()
            if tp_s:
                tp_int = int(tp_s)
                if tp_int <= 0 or tp_int > 100000:
                    raise ValueError("Invalid top-ports")
                tp = tp_int

        ps = (ports or "").strip()
        if tp is None:
            ps = validate_ports(ps)
        else:
            # store for visibility; nmap_runner uses top_ports for actual scan
            if not ps:
                ps = f"--top-ports {tp}"

        ex_list = sanitize_extra_args(extra or "")

        if ALLOWED_TARGETS and not target_allowed(tlist, ALLOWED_TARGETS):
            raise ValueError("Target out of allowed range (ALLOWED_TARGETS)")
    except Exception as e:
        return templates.TemplateResponse("run_scan.html", {"request": req, "error": str(e), "run": None})

    xml_id = uuid.uuid4().hex
    xml_path, log_path = nmap_runner.build_paths(xml_id)

    run = models.ScanRun(
        xml_id=xml_id,
        scan_name=(scan_name or "").strip() or None,
        target_spec=targets.strip(),
        ports_spec=ps,
        extra_args=" ".join(ex_list),
        firewall_blocked=fw_val,
        status="RUNNING",
        started_at=datetime.utcnow(),
        xml_path=xml_path,
        log_path=log_path,
        executed_by=u.id,
    )
    db.add(run)
    db.commit()
    # persist normalized port-scope coverage for this run (auditable / safe miss accounting)
    try:
        run.scan_type = stype
        db.commit()
    except Exception:
        pass
    try:
        crud.save_run_scope(db, run.id, stype, ps, tp)
    except Exception:
        pass
    crud.add_audit(db, u.id, "SCAN_START", "scan_run", str(run.id), None, {"xml_id": xml_id}, client_ip(req))

    rp = nmap_runner.start_scan(xml_id, tlist, None if tp is not None else ps, ex_list, scan_type=stype, top_ports=tp)
    try:
        run.executed_command = " ".join(__import__('shlex').quote(x) for x in getattr(rp, 'cmd', []))
        db.commit()
    except Exception:
        pass

    return templates.TemplateResponse("run_scan.html", {"request": req, "error": None, "run": run})

@app.get("/scan/{xml_id}/stream")
def stream_log(xml_id: str, req: Request, db: Session = Depends(get_db)):
    # scan execution is an admin capability; avoid leaking log output via direct URL.
    u = inject_ctx(req, db)
    if not require_admin(u):
        return Response(status_code=403)

    def gen():
        while True:
            tail = nmap_runner.read_log_tail(xml_id)
            yield "data: " + json.dumps(tail)[1:-1] + "\n\n"
            if nmap_runner.scan_finished(xml_id):
                break
            import time; time.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream")

@app.post("/scan/{xml_id}/stop")
def stop_scan(xml_id: str, req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return JSONResponse({"ok": False}, status_code=403)
    ok = nmap_runner.stop_scan(xml_id)
    run = db.execute(select(models.ScanRun).where(models.ScanRun.xml_id==xml_id)).scalar_one_or_none()
    if run:
        run.status = "STOPPED"
        run.finished_at = datetime.utcnow()
        db.commit()
    crud.add_audit(db, u.id, "SCAN_STOP", "scan_run", xml_id, None, {"stopped": ok}, client_ip(req))
    return {"ok": ok}


@app.post("/scan/{run_id}/delete")
def delete_scan_run(run_id: int, req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)

    run = db.get(models.ScanRun, run_id)
    if not run:
        return RedirectResponse("/", status_code=302)

    if run.status == "DONE":
        return RedirectResponse(f"/scan/{run_id}", status_code=302)

    # Delete child rows first to avoid FK violations (Postgres).
    try:
        scope_ids = db.execute(
            select(models.ScanRunPortScope.id).where(models.ScanRunPortScope.run_id == run.id)
        ).scalars().all()
        if scope_ids:
            db.execute(models.ScanRunPortRange.__table__.delete().where(models.ScanRunPortRange.scope_id.in_(scope_ids)))
        db.execute(models.ScanRunPortScope.__table__.delete().where(models.ScanRunPortScope.run_id == run.id))
        db.execute(models.ScanRunHost.__table__.delete().where(models.ScanRunHost.run_id == run.id))
    except Exception:
        pass

    db.execute(models.RunOpenPort.__table__.delete().where(models.RunOpenPort.run_id == run.id))
    db.execute(models.PortEvent.__table__.delete().where(models.PortEvent.scan_run_id == run.id))
    import os
    for p in [run.xml_path, run.log_path]:
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except Exception:
            pass

    db.delete(run)
    db.commit()
    crud.add_audit(db, u.id, "SCAN_DELETE", "scan_run", str(run_id), None, {"status": run.status}, client_ip(req))
    return RedirectResponse("/", status_code=302)

@app.post("/scan/{run_id}/ingest")
def ingest_scan(run_id: int, req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return JSONResponse({"ok": False}, status_code=403)
    run = crud.get_scan_run(db, run_id)
    if not run:
        return {"ok": False, "error": "not found"}
    try:
        observed, hosts = nmap_runner.parse_nmap_xml(run.xml_path)
        try:
            crud.save_run_hosts(db, run.id, hosts)
        except Exception:
            pass
        crud.upsert_inventory_and_events(db, run, run.firewall_blocked, observed)
        run.status = "SUCCESS"
        run.finished_at = datetime.utcnow()
        db.commit()

        # Cleanup: once successfully ingested, remove the raw scan artifacts to prevent unbounded growth.
        import os
        for p in [getattr(run, "xml_path", None), getattr(run, "log_path", None)]:
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        crud.add_audit(db, u.id, "SCAN_INGEST", "scan_run", str(run.id), None, {"observed": len(observed)}, client_ip(req))
        return RedirectResponse(f"/scan/{run.id}", status_code=302)
    except Exception as e:
        run.status = "PARSE_FAILED"
        run.error_message = str(e)
        run.finished_at = datetime.utcnow()
        db.commit()
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)

@app.get("/audit", response_class=HTMLResponse)
def audit_page(
    req: Request,
    start: str | None = None,
    end: str | None = None,
    user: str | None = None,
    action: str | None = None,
    db: Session = Depends(get_db),
):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)

    start_s = (start or "").strip()
    end_s = (end or "").strip()
    user_q = (user or "").strip()
    action_q = (action or "").strip()

    q = select(models.AuditLog).order_by(models.AuditLog.at.desc()).limit(500)
    if start_s:
        q = q.where(models.AuditLog.at >= kst_date_to_utc_start(start_s))
    if end_s:
        # inclusive end-day
        q = q.where(models.AuditLog.at < kst_date_to_utc_end_exclusive(end_s))
    if action_q:
        q = q.where(models.AuditLog.action.ilike(f"%{action_q}%"))

    if user_q:
        # join users for filtering
        q = q.join(models.User, isouter=True).where(models.User.user_id.ilike(f"%{user_q}%"))

    rows = db.execute(q).scalars().all()
    # ensure user relationship loaded
    return templates.TemplateResponse(
        "audit.html",
        {"request": req, "rows": rows, "start": start_s, "end": end_s, "user_q": user_q, "action_q": action_q},
    )

@app.get("/export/audit")
def export_audit(
    req: Request,
    start: str | None = None,
    end: str | None = None,
    user: str | None = None,
    action: str | None = None,
    db: Session = Depends(get_db),
):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)

    start_s = (start or "").strip()
    end_s = (end or "").strip()
    user_q = (user or "").strip()
    action_q = (action or "").strip()

    q = select(models.AuditLog).order_by(models.AuditLog.at.desc()).limit(5000)
    if start_s:
        q = q.where(models.AuditLog.at >= kst_date_to_utc_start(start_s))
    if end_s:
        q = q.where(models.AuditLog.at < kst_date_to_utc_end_exclusive(end_s))
    if action_q:
        q = q.where(models.AuditLog.action.ilike(f"%{action_q}%"))
    if user_q:
        q = q.join(models.User, isouter=True).where(models.User.user_id.ilike(f"%{user_q}%"))

    rows = db.execute(q).scalars().all()
    headers = ["At (KST)","User","Action","Object","Source IP","Result"]
    data = []
    for r in rows:
        data.append([
            to_kst(r.at),
            (r.user.user_id if getattr(r, "user", None) else ""),
            r.action,
            f"{r.object_type}:{r.object_key}",
            r.source_ip or "",
            r.after or "",
        ])

    content = make_xlsx_bytes("Audit", headers, data)
    fname = "myscanner_audit.xlsx"
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )

@app.get("/users", response_class=HTMLResponse)
def users_page(req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)
    users = crud.list_users(db)
    return templates.TemplateResponse("users.html", {"request": req, "users": users, "msg": None, "error": None})



@app.post("/users/{user_pk}/action", response_class=HTMLResponse)
def users_action(req: Request, user_pk: int, action: str = Form(...), db: Session = Depends(get_db)):
    admin = inject_ctx(req, db)
    if not require_admin(admin):
        return RedirectResponse("/", status_code=302)

    msg = None
    error = None
    if action == "reset_pw":
        new_pw = generate_temp_password()
        tgt = crud.get_user(db, user_pk)
        if not tgt:
            error = "User not found"
        else:
            tgt.password_hash = hash_password(new_pw)
            tgt.must_change_password = True
            db.commit()
            # revoke existing sessions
            sessions = db.execute(select(models.Session).where(models.Session.user_id == tgt.id, models.Session.revoked == False)).scalars().all()
            for s in sessions:
                s.revoked = True
            db.commit()
            crud.add_audit(db, admin.id, "USER_PW_RESET", "user", tgt.user_id, None, {"temp_pw_issued": True, "must_change_password": True}, client_ip(req))
            msg = f"Reset done. Temp PW: {new_pw}"

    elif action == "reset_mfa":
        tgt = crud.reset_user_mfa(db, user_pk)
        if not tgt:
            error = "User not found"
        else:
            sessions = db.execute(select(models.Session).where(models.Session.user_id == tgt.id, models.Session.revoked == False)).scalars().all()
            for s in sessions:
                s.revoked = True
            db.commit()
            crud.add_audit(db, admin.id, "USER_MFA_RESET", "user", tgt.user_id, None, {"mfa": "reset"}, client_ip(req))
            msg = "MFA reset done."

    elif action == "force_logout":
        sessions = db.execute(select(models.Session).where(models.Session.user_id == user_pk, models.Session.revoked == False)).scalars().all()
        for s in sessions:
            s.revoked = True
        db.commit()
        crud.add_audit(db, admin.id, "USER_FORCE_LOGOUT", "user", str(user_pk), None, {"sessions_revoked": len(sessions)}, client_ip(req))
        msg = "Force logout done."

    elif action == "delete_user":
        if admin and admin.id == user_pk:
            error = "You cannot delete your own account while logged in."
        else:
            tgt = crud.get_user(db, user_pk)
            if not tgt:
                error = "User not found"
            else:
                try:
                    stats = crud.delete_user(db, user_pk)
                    crud.add_audit(
                        db,
                        admin.id,
                        "USER_DELETE",
                        "user",
                        tgt.user_id,
                        {"role": tgt.role, "email": tgt.email},
                        {"deleted": True, **(stats or {})},
                        client_ip(req),
                    )
                    msg = f"User deleted: {tgt.user_id}"
                except ValueError as ve:
                    error = str(ve)

    else:
        error = "Unknown action"

    users = crud.list_users(db)
    return templates.TemplateResponse("users.html", {"request": req, "users": users, "msg": msg, "error": error})

@app.post("/users/{user_pk}/reset", response_class=HTMLResponse)
def users_reset(req: Request, user_pk: int, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)
    new_pw = generate_temp_password()
    tgt = crud.reset_user_password(db, user_pk, hash_password(new_pw))
    if tgt:
        tgt.must_change_password = True
        db.commit()
        # security: invalidate existing sessions after password reset
        sessions = db.execute(select(models.Session).where(models.Session.user_id==tgt.id, models.Session.revoked==False)).scalars().all()
        for s in sessions:
            s.revoked = True
        db.commit()
        crud.add_audit(db, u.id, "USER_PW_RESET", "user", tgt.user_id, None, {"temp_pw_issued": True, "must_change_password": True}, client_ip(req))
    users = crud.list_users(db)
    return templates.TemplateResponse("users.html", {"request": req, "users": users, "msg": f"Reset done. Temp PW: {new_pw}", "error": None})


@app.post("/users/{user_pk}/reset_mfa", response_class=HTMLResponse)
def users_reset_mfa(req: Request, user_pk: int, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)
    tgt = crud.reset_user_mfa(db, user_pk)
    if tgt:
        # revoke sessions so user must re-login and re-enroll MFA
        sessions = db.execute(select(models.Session).where(models.Session.user_id==tgt.id, models.Session.revoked==False)).scalars().all()
        for s in sessions:
            s.revoked = True
        db.commit()
        crud.add_audit(db, u.id, "USER_MFA_RESET", "user", tgt.user_id, None, {"mfa": "reset"}, client_ip(req))
    users = crud.list_users(db)
    return templates.TemplateResponse("users.html", {"request": req, "users": users, "msg": "MFA reset done.", "error": None})

@app.post("/users/{user_pk}/logout", response_class=HTMLResponse)
def users_logout(req: Request, user_pk: int, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not require_admin(u):
        return RedirectResponse("/", status_code=302)
    sessions = db.execute(select(models.Session).where(models.Session.user_id==user_pk, models.Session.revoked==False)).scalars().all()
    for s in sessions:
        s.revoked = True
    db.commit()
    crud.add_audit(db, u.id, "USER_FORCE_LOGOUT", "user", str(user_pk), None, {"sessions_revoked": len(sessions)}, client_ip(req))
    users = crud.list_users(db)
    return templates.TemplateResponse("users.html", {"request": req, "users": users, "msg": "Force logout done.", "error": None})

@app.get("/export/results")
def export_results(
    req: Request,
    start: str | None = None,
    end: str | None = None,
    fw: str | None = None,
    db: Session = Depends(get_db),
):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    fw_val = fw if fw in ("Y","N") else ""
    open_only_bool = True

    rows = []
    if start and end:
        sdt = datetime.fromisoformat(start).replace(tzinfo=KST).astimezone(UTC).replace(tzinfo=None)
        edt = (datetime.fromisoformat(end) + timedelta(days=1)).replace(tzinfo=KST).astimezone(UTC).replace(tzinfo=None)
        rows = crud.query_inventory(db, sdt, edt, fw_val if fw_val else None)

    headers = [
        "Latest Date (KST)",
        "IP",
        "Port",
        "Service",
        "FW",
        "Hostname",
        "Operator",
        "Owner",
        "Ticket/Evidence",
        "Comment",
        "Status",
        "Reviewed",
        "Inactive",
        "Remediation note",
    ]
    data = []
    for r in rows:
        eff_status = ("INACTIVE" if getattr(r, "inactive", False) else getattr(r, "status", "ACTIVE"))
        data.append([
            to_kst(r.latest_seen_at),
            r.ip,
            r.port,
            r.service_latest or "",
            r.firewall_blocked,
            r.hostname or "",
            getattr(r, "operator", "") or "",
            getattr(r, "owner", "") or "",
            getattr(r, "ticket", "") or "",
            r.comment or "",
            eff_status,
            "Y" if r.reviewed else "N",
            "Y" if r.inactive else "N",
            getattr(r, "remediation_note", "") or "",
        ])

    content = make_xlsx_bytes("Results", headers, data)
    fname = "myscanner_results.xlsx"
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/export/triage")
def export_triage(
    req: Request,
    fw: str | None = None,
    status: str | None = None,
    ip: str | None = None,
    port: str | None = None,
    owner: str | None = None,
    operator: str | None = None,
    comment: str | None = None,
    db: Session = Depends(get_db),
):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    fw_val = fw if fw in ("Y","N") else ""
    status_val = status if status in ("ACTIVE","DENIED") else ""
    ip_q = ip.strip() if ip else ""
    port_q = port.strip() if port else ""
    owner_q = owner.strip() if owner else ""
    operator_q = operator.strip() if operator else ""
    comment_q = comment.strip() if comment else ""

    rows = crud.query_triage(
        db,
        fw_val if fw_val else None,
        status_val if status_val else None,
        ip_q if ip_q else None,
        port_q if port_q else None,
        owner_q if owner_q else None,
        operator_q if operator_q else None,
        comment_q if comment_q else None,
    )

    headers = ["Latest Date (KST)","IP","Port","Service","FW","Hostname","Operator","Owner","Ticket/Evidence","Comment","Status"]
    data = []
    for r in rows:
        data.append([
            to_kst(r.latest_seen_at),
            r.ip,
            r.port,
            r.service_latest or "",
            r.firewall_blocked,
            r.hostname or "",
            getattr(r, "operator", "") or "",
            getattr(r, "owner", "") or "",
            getattr(r, "ticket", "") or "",
            r.comment or "",
            getattr(r, "status", "ACTIVE"),
        ])

    content = make_xlsx_bytes("Triage", headers, data)
    fname = "myscanner_triage.xlsx"
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/export/remediated")
def export_remediated(
    req: Request,
    fw: str | None = None,
    status: str | None = None,
    ip: str | None = None,
    port: str | None = None,
    db: Session = Depends(get_db),
):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    fw_val = fw if fw in ("Y","N") else ""
    status_val = status if status in ("REMEDIATED","IGNORED","INACTIVE") else ""
    ip_q = ip.strip() if ip else ""
    port_q = port.strip() if port else ""

    inv = models.PortInventory
    q = select(inv).where((inv.status.in_(("REMEDIATED","IGNORED"))) | (inv.inactive == True))
    if fw_val:
        q = q.where(inv.firewall_blocked == fw_val)
    if status_val == "INACTIVE":
        q = q.where(inv.inactive == True)
    elif status_val in ("REMEDIATED","IGNORED"):
        q = q.where(inv.status == status_val)
    if ip_q:
        q = q.where(inv.ip == ip_q)
    if port_q:
        if port_q.isdigit():
            q = q.where(inv.port == int(port_q))

    rows = db.execute(q.order_by(inv.ip.asc(), inv.port.asc())).scalars().all()

    headers = ["Latest Date (KST)","IP","Port","Service","FW","Hostname","Operator","Owner","Ticket/Evidence","Comment","Status","Inactive","Remediation note"]
    data = []
    for r in rows:
        eff_status = ("INACTIVE" if getattr(r, "inactive", False) else getattr(r, "status", "ACTIVE"))
        data.append([
            to_kst(r.latest_seen_at),
            r.ip,
            r.port,
            r.service_latest or "",
            r.firewall_blocked,
            r.hostname or "",
            getattr(r, "operator", "") or "",
            getattr(r, "owner", "") or "",
            getattr(r, "ticket", "") or "",
            r.comment or "",
            eff_status,
            "Y" if r.inactive else "N",
            getattr(r, "remediation_note", "") or "",
        ])

    content = make_xlsx_bytes("Remediated", headers, data)
    fname = "myscanner_remediated.xlsx"
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/export/assets")
def export_assets(req: Request, db: Session = Depends(get_db)):
    u = inject_ctx(req, db)
    if not u:
        return RedirectResponse("/login", status_code=302)

    rows = crud.list_assets(db)
    headers = ["IP","Hostname","Owner","Last Seen (KST)"]
    data = []
    for ip, last_seen_at, host, operator, owner in rows:
        data.append([ip, host or "", owner or "", to_kst(last_seen_at)])

    content = make_xlsx_bytes("Assets", headers, data)
    fname = "myscanner_assets.xlsx"
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
