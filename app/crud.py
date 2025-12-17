from __future__ import annotations
from datetime import datetime, timedelta
import secrets, json
from sqlalchemy import select, and_, func, cast, String, update
from sqlalchemy.orm import Session
from app import models
from app.security import new_session_id, session_expiry


def _parse_ports_spec(ports_spec: str):
    """Parse ports_spec like '80,443,1-1024' to (singles:set[int], ranges:list[tuple[int,int]]).
    Returns None if scope is unknown (e.g. '--top-ports N').
    """
    ps = (ports_spec or "").strip()
    if not ps:
        return set(), []
    if ps.startswith("--top-ports"):
        return None
    singles: set[int] = set()
    ranges: list[tuple[int,int]] = []
    for part in ps.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "-":
            continue
        if "-" in part:
            a,b = part.split("-", 1)
            a=a.strip(); b=b.strip()
            if not a.isdigit() or not b.isdigit():
                continue
            ai=int(a); bi=int(b)
            if ai>bi: ai,bi = bi,ai
            ranges.append((ai,bi))
        else:
            if part.isdigit():
                singles.add(int(part))
    return singles, ranges

def _port_in_scope(port: int, scope):
    """Return True if port is within scope.

    scope forms:
      - (singles:set[int], ranges:list[(a,b)]) from _parse_ports_spec
      - list[(a,b)] explicit ranges from scan_run_port_ranges
    """
    if scope is None:
        return False
    # normalized ranges-only form
    if isinstance(scope, list) and scope and isinstance(scope[0], tuple) and len(scope[0]) == 2 and isinstance(scope[0][0], int):
        for a, b in scope:
            if a <= port <= b:
                return True
        return False
    singles, ranges = scope
    if port in singles:
        return True
    for a, b in ranges:
        if a <= port <= b:
            return True
    return False



def save_run_scope(db: Session, run_id: int, proto: str, ports_spec: str, top_ports: int | None):
    """Persist normalized 'this scan covered which ports' for auditable miss accounting.

    - explicit: store port ranges parsed from ports_spec
    - top_ports: scope_kind=top_ports (miss accounting disabled for safety)
    """
    pr = "udp" if (proto or "").lower() == "udp" else "tcp"

    # delete existing scope for (run,proto)
    existing = db.execute(
        select(models.ScanRunPortScope).where(
            models.ScanRunPortScope.run_id == run_id,
            models.ScanRunPortScope.proto == pr,
        )
    ).scalar_one_or_none()
    if existing:
        db.delete(existing)
        db.commit()

    scope_kind = "explicit"
    raw = (ports_spec or "").strip()

    tp = None
    if top_ports is not None:
        scope_kind = "top_ports"
        tp = int(top_ports)
    elif raw.lower().startswith("--top-ports"):
        scope_kind = "top_ports"
        try:
            tp = int(raw.split()[-1])
        except Exception:
            tp = None

    scope = models.ScanRunPortScope(run_id=run_id, proto=pr, scope_kind=scope_kind, raw_spec=raw or None, top_ports=tp)
    db.add(scope)
    db.commit()

    # store ranges only if explicit
    if scope_kind != "explicit":
        return

    singles, ranges = _parse_ports_spec(raw)
    # normalize singles to ranges
    for p in sorted(singles):
        ranges.append((p, p))
    if not ranges:
        # should not happen (ports required), but keep safe default
        ranges = [(1, 65535)]

    for a, b in ranges:
        if a > b:
            a, b = b, a
        db.add(models.ScanRunPortRange(scope_id=scope.id, port_start=int(a), port_end=int(b)))
    db.commit()


def save_run_hosts(db: Session, run_id: int, hosts: list[dict]):
    """Persist hosts seen in the XML for this scan run."""
    # clear existing
    db.execute(models.ScanRunHost.__table__.delete().where(models.ScanRunHost.run_id == run_id))
    for h in hosts or []:
        ip = (h.get("ip") or "").strip()
        if not ip:
            continue
        is_up = bool(h.get("is_up", True))
        db.add(models.ScanRunHost(run_id=run_id, ip=ip, is_up=is_up))
    db.commit()


def get_run_port_scope(db: Session, run_id: int, proto: str) -> list[tuple[int, int]] | None:
    """Return list of (start,end) ranges for this run's port coverage.

    Returns None if scope is unknown (e.g., --top-ports) => miss accounting disabled.
    """
    pr = "udp" if (proto or "").lower() == "udp" else "tcp"
    scope = db.execute(
        select(models.ScanRunPortScope).where(
            models.ScanRunPortScope.run_id == run_id,
            models.ScanRunPortScope.proto == pr,
        )
    ).scalar_one_or_none()
    if not scope:
        return None
    if (scope.scope_kind or "").lower() != "explicit":
        return None
    rows = db.execute(
        select(models.ScanRunPortRange.port_start, models.ScanRunPortRange.port_end)
        .where(models.ScanRunPortRange.scope_id == scope.id)
    ).all()
    return [(int(a), int(b)) for a, b in rows] if rows else [(1, 65535)]

def add_audit(db: Session, user_id, action: str, obj_type: str, obj_key: str, before=None, after=None, source_ip=None):
    rec = models.AuditLog(
        user_id=user_id,
        action=action,
        object_type=obj_type,
        object_key=obj_key,
        before=json.dumps(before, ensure_ascii=False) if before is not None else None,
        after=json.dumps(after, ensure_ascii=False) if after is not None else None,
        source_ip=source_ip,
    )
    db.add(rec)
    db.commit()

def get_user_by_user_id(db: Session, user_id: str):
    return db.execute(select(models.User).where(models.User.user_id == user_id)).scalar_one_or_none()

def get_user(db: Session, user_pk: int):
    return db.get(models.User, user_pk)

def create_session(db: Session, user: models.User):
    sid = new_session_id()
    exp = session_expiry()
    s = models.Session(session_id=sid, user_id=user.id, expires_at=exp)
    db.add(s)
    db.commit()
    return sid, exp

def get_session(db: Session, sid: str):
    return db.execute(select(models.Session).where(models.Session.session_id == sid)).scalar_one_or_none()

def revoke_session(db: Session, sid: str):
    s = get_session(db, sid)
    if s:
        s.revoked = True
    db.commit()

def create_preauth(db: Session, user: models.User, ttl_minutes: int = 10) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.utcnow()
    pa = models.PreAuthSession(token=token, user_id=user.id, created_at=now, expires_at=now + timedelta(minutes=ttl_minutes))
    db.add(pa)
    db.commit()
    return token

def get_preauth(db: Session, token: str):
    if not token:
        return None
    return db.execute(select(models.PreAuthSession).where(models.PreAuthSession.token == token)).scalar_one_or_none()

def delete_preauth(db: Session, token: str):
    pa = get_preauth(db, token)
    if pa:
        db.delete(pa)
    db.commit()

def list_scan_runs(db: Session, limit: int = 50):
    return db.execute(select(models.ScanRun).order_by(models.ScanRun.started_at.desc()).limit(limit)).scalars().all()

def get_scan_run(db: Session, run_id: int):
    return db.get(models.ScanRun, run_id)


def latest_finished_run(db: Session, firewall_blocked: str | None = None):
    q = select(models.ScanRun).where(models.ScanRun.status.in_(("SUCCESS","DONE"))).where(models.ScanRun.finished_at.is_not(None))
    if firewall_blocked in ("Y","N"):
        q = q.where(models.ScanRun.firewall_blocked == firewall_blocked)
    return db.execute(q.order_by(models.ScanRun.finished_at.desc())).scalars().first()



def count_run_open_ports(db: Session, run_id: int):
    return db.execute(
        select(func.count()).select_from(models.RunOpenPort).where(models.RunOpenPort.run_id == run_id)
    ).scalar_one()

def count_total_active_open_ports(db: Session, firewall_blocked: str | None = None):
    q = (
        select(func.count())
        .select_from(models.PortInventory)
        .where(models.PortInventory.state_latest == "open")
        .where(models.PortInventory.inactive == False)
        .where(models.PortInventory.status.in_(("ACTIVE","DENIED")))
    )
    if firewall_blocked in ("Y","N"):
        q = q.where(models.PortInventory.firewall_blocked == firewall_blocked)
    return db.execute(q).scalar_one()

def previous_finished_run_same_profile(db: Session, run: models.ScanRun):
    """Return the most recent finished run before `run` with the same firewall profile.
    This is used for 'gone port' detection when a previously open port is no longer open.
    """
    q = (
        select(models.ScanRun)
        .where(models.ScanRun.status.in_(("SUCCESS","DONE")))
        .where(models.ScanRun.finished_at.is_not(None))
        .where(models.ScanRun.firewall_blocked == run.firewall_blocked)
        .where(models.ScanRun.id != run.id)
    )
    if run.started_at is not None:
        q = q.where(models.ScanRun.finished_at < run.started_at)
    return db.execute(q.order_by(models.ScanRun.finished_at.desc())).scalars().first()


def run_open_set(db: Session, run_id: int, firewall_blocked: str | None = None) -> set[tuple[str, int]]:
    """Return set of (ip, port) that were open in a given scan run."""
    q = select(models.RunOpenPort.ip, models.RunOpenPort.port).where(models.RunOpenPort.run_id == run_id)
    if firewall_blocked in ("Y", "N"):
        q = q.where(models.RunOpenPort.firewall_blocked == firewall_blocked)
    rows = db.execute(q).all()
    return {(ip, int(port)) for (ip, port) in rows}


def upsert_inventory_and_events(db: Session, run: models.ScanRun, firewall_blocked: str, observed: list[dict]):
    """Upsert inventory rows for OPEN ports only + emit events + store per-run open snapshot.

    Notes:
    - We only track OPEN ports in PortInventory / RunOpenPort.
    - Operator-entered fields are reused across firewall profiles to avoid duplicate triage input:
      * Hostname/Operator/Owner: reused by IP (latest non-null)
      * Comment/Ticket/Status/Reviewed: reused by (IP,Port) (latest)
    """
    # Clear previous snapshot for this run (re-ingest safety)
    db.execute(models.RunOpenPort.__table__.delete().where(models.RunOpenPort.run_id == run.id))

    ts = run.finished_at or datetime.utcnow()
    current_open: set[tuple[str, int]] = set()
    scanned_ips: set[str] = set()  # IPs included in this ingest (from XML)

    # caches to reduce DB lookups
    ip_meta_cache: dict[str, dict] = {}
    port_meta_cache: dict[tuple[str, int], dict] = {}

    def _latest_ip_meta(ip: str) -> dict:
        if ip in ip_meta_cache:
            return ip_meta_cache[ip]

        def _latest(field_name: str):
            col = getattr(models.PortInventory, field_name)
            row = db.execute(
                select(col)
                .where(models.PortInventory.ip == ip)
                .where(col.is_not(None))
                .order_by(models.PortInventory.latest_seen_at.desc())
                .limit(1)
            ).first()
            return row[0] if row else None

        meta = {
            "hostname": _latest("hostname"),
            "operator": _latest("operator"),
            "owner": _latest("owner"),
        }
        ip_meta_cache[ip] = meta
        return meta
    def _latest_port_meta(ip: str, port: int) -> dict:
        key = (ip, port)
        if key in port_meta_cache:
            return port_meta_cache[key]

        inv_any = db.execute(
            select(models.PortInventory)
            .where(models.PortInventory.ip == ip)
            .where(models.PortInventory.port == port)
            .order_by(models.PortInventory.latest_seen_at.desc())
            .limit(1)
        ).scalars().first()

        # Status is chosen with precedence across firewall profiles to avoid split-brain triage states.
        # NOTE: INACTIVE is a separate lifecycle flag (misses>=2) and is NOT treated as a status.
        # Precedence (highest -> lowest): DENIED > REMEDIATED > IGNORED > ACTIVE
        statuses = db.execute(
            select(models.PortInventory.status)
            .where(models.PortInventory.ip == ip)
            .where(models.PortInventory.port == port)
        ).scalars().all()
        order = ["DENIED", "REMEDIATED", "IGNORED", "ACTIVE"]
        picked_status = "ACTIVE"
        norm = [((s or "ACTIVE").strip().upper()) for s in statuses]
        for s in order:
            if s in norm:
                picked_status = s
                break

        meta = {
            "comment": getattr(inv_any, "comment", None) if inv_any else None,
            "ticket": getattr(inv_any, "ticket", None) if inv_any else None,
            "reviewed": bool(getattr(inv_any, "reviewed", False)) if inv_any else False,
            "status": (picked_status or "ACTIVE").strip().upper(),
        }
        port_meta_cache[key] = meta
        return meta


    firewall = firewall_blocked if firewall_blocked in ("Y", "N") else "N"

    # normalized port-scope for this scan (explicit ranges) - miss accounting uses this
    scan_proto = getattr(run, 'scan_type', 'tcp') or 'tcp'
    port_scope = None
    try:
        port_scope = get_run_port_scope(db, run.id, scan_proto)
    except Exception:
        port_scope = None
    if port_scope is None:
        # fallback for older runs (pre-scope table)
        port_scope = _parse_ports_spec(run.ports_spec)

    # Ingest OPEN ports only
    for row in observed:
        ip = row.get("ip")
        if not ip:
            continue

        scanned_ips.add(ip)
        port = int(row.get("port"))
        state = row.get("state")
        service = row.get("service")

        if state != "open":
            continue

        current_open.add((ip, port))

        # Any observation of OPEN resets misses/inactive across FW profiles for the same IP/Port.
        # Additionally, if the port was previously INACTIVE (misses>=2), force re-triage by resetting
        # Reviewed=False and returning status back to ACTIVE (except DENIED stays DENIED).
        try:
            from sqlalchemy import case
            inv_tbl = models.PortInventory.__table__
            db.execute(
                inv_tbl.update()
                .where(inv_tbl.c.ip == ip)
                .where(inv_tbl.c.port == port)
                .where(inv_tbl.c.inactive == True)
                .values(
                    open_misses=0,
                    inactive=False,
                    reviewed=False,
                    remediation_at=None,
                    status=case(
                        (inv_tbl.c.status == "DENIED", "DENIED"),
                        else_="ACTIVE",
                    ),
                )
            )
        except Exception:
            pass

        db.execute(
            models.PortInventory.__table__.update()
            .where(models.PortInventory.ip == ip)
            .where(models.PortInventory.port == port)
            .values(open_misses=0, inactive=False)
        )


        # store per-run snapshot
        db.add(models.RunOpenPort(run_id=run.id, ip=ip, port=port, firewall_blocked=firewall))

        inv = db.execute(
            select(models.PortInventory).where(
                models.PortInventory.ip == ip,
                models.PortInventory.port == port,
                models.PortInventory.firewall_blocked == firewall,
            )
        ).scalars().first()

        if inv is None:
            ip_meta = _latest_ip_meta(ip)
            port_meta = _latest_port_meta(ip, port)

            inv = models.PortInventory(
                ip=ip,
                port=port,
                firewall_blocked=firewall,
                first_seen_at=run.started_at or ts,
                latest_seen_at=ts,
                state_latest="open",
                service_latest=service,
                hostname=ip_meta.get("hostname"),
                operator=ip_meta.get("operator"),
                owner=ip_meta.get("owner"),
                comment=port_meta.get("comment"),
                ticket=port_meta.get("ticket"),
                reviewed=port_meta.get("reviewed", False),
                status=((port_meta.get("status") or "ACTIVE").strip().upper()),
                open_misses=0,
                inactive=False,
            )
            db.add(inv)

            db.add(
                models.PortEvent(
                    ip=ip,
                    port=port,
                    firewall_blocked=firewall,
                    scan_run_id=run.id,
                    event_type="FIRST_SEEN",
                    prev_state=None,
                    new_state="open",
                    prev_service=None,
                    new_service=service,
                    event_time=ts,
                )
            )
        else:
            prev_state = inv.state_latest
            prev_service = inv.service_latest

            inv.latest_seen_at = ts
            inv.state_latest = "open"
            inv.service_latest = service
            inv.open_misses = 0
            inv.inactive = False

            # Reuse operator-entered data across firewall profiles / repeated scans (fill only if missing)
            ip_meta = _latest_ip_meta(ip)
            port_meta = _latest_port_meta(ip, port)

            if inv.hostname is None and ip_meta.get("hostname"):
                inv.hostname = ip_meta.get("hostname")
            if inv.operator is None and ip_meta.get("operator"):
                inv.operator = ip_meta.get("operator")
            if inv.owner is None and ip_meta.get("owner"):
                inv.owner = ip_meta.get("owner")
            if inv.comment is None and port_meta.get("comment"):
                inv.comment = port_meta.get("comment")
            if inv.ticket is None and port_meta.get("ticket"):
                inv.ticket = port_meta.get("ticket")
            if inv.reviewed is False and port_meta.get("reviewed"):
                inv.reviewed = True
            meta_status = (port_meta.get("status") or "ACTIVE").strip().upper()
            # If an IP/Port is already treated as remediated/ignored/inactive (any firewall profile),
            # keep it out of the ACTIVE triage queue even when scanned again under a different profile.
            if meta_status in ("DENIED", "REMEDIATED", "IGNORED") and (inv.status or "ACTIVE").strip().upper() in ("ACTIVE", "DENIED"):
                inv.status = meta_status

            if prev_state != inv.state_latest or prev_service != inv.service_latest:
                db.add(
                    models.PortEvent(
                        ip=ip,
                        port=port,
                        firewall_blocked=firewall,
                        scan_run_id=run.id,
                        event_type="STATE_CHANGED",
                        prev_state=prev_state,
                        new_state=inv.state_latest,
                        prev_service=prev_service,
                        new_service=inv.service_latest,
                        event_time=ts,
                    )
                )

        # Prefer host list from XML (scan_run_hosts) so we only mark misses for targets actually scanned
    try:
        host_rows = db.execute(select(models.ScanRunHost.ip).where(models.ScanRunHost.run_id == run.id)).all()
        if host_rows:
            scanned_ips = {r[0] for r in host_rows if r and r[0]}
    except Exception:
        pass

# Mark missing OPEN ports as "missed" for this scan (FW-agnostic).
    # If a port is not observed OPEN for 2 consecutive ingests, mark it inactive.
    inv = models.PortInventory

    # Only count misses for ports that were actually in-scope for this scan run.
    # If scope is unknown (e.g. top-ports), we do NOT increment misses.
    if port_scope is not None and scanned_ips:
        q_prev = (
            select(inv.ip, inv.port, func.max(inv.open_misses))
            .where(inv.inactive == False)
            .where(inv.state_latest == "open")
            .where(inv.ip.in_(scanned_ips))
            .group_by(inv.ip, inv.port)
        )
        prev_rows = db.execute(q_prev).all()

        # Keep only ports that were explicitly in-scope for this run.
        prev_rows = [
            (ip, int(port), max_misses)
            for (ip, port, max_misses) in prev_rows
            if _port_in_scope(int(port), port_scope)
        ]

        for ip, port, max_misses in prev_rows:
            key = (ip, int(port))
            if key not in current_open:
                new_misses = int(max_misses or 0) + 1
                vals = {"open_misses": new_misses}
                if new_misses >= 2:
                    vals["inactive"] = True
                db.execute(
                    inv.__table__.update()
                    .where(inv.ip == ip)
                    .where(inv.port == int(port))
                    .values(**vals)
                )


def query_triage(
    db: Session,
    firewall_blocked: str | None,
    status_filter: str | None,
    ip_q: str | None,
    port_q: str | None,
    owner_q: str | None,
    operator_q: str | None,
    comment_q: str | None,
):
    """Triage Queue (inventory):
    - open + not inactive
    - status in ACTIVE/DENIED
    - includes all DENIED, plus ACTIVE needing triage (unreviewed or missing required fields)
    - Filters are AND-combined when provided.
      * IP/Port: exact match
      * Owner/Operator: exact match, case-insensitive (A안: strip only)
      * Comment: substring match (ILIKE)
    """
    inv = models.PortInventory

    base = (
        select(inv)
        .where(inv.state_latest == "open")
        .where(inv.inactive == False)
        .where(inv.status.in_(("ACTIVE", "DENIED")))
    )

    needs_triage_active = (
        (inv.reviewed == False)
        | (inv.hostname.is_(None))
        | (inv.operator.is_(None))
        | (inv.owner.is_(None))
        | (inv.ticket.is_(None))
        | (inv.comment.is_(None))
    )
    base = base.where((inv.status == "DENIED") | ((inv.status == "ACTIVE") & (needs_triage_active)))

    if firewall_blocked in ("Y", "N"):
        base = base.where(inv.firewall_blocked == firewall_blocked)
    if status_filter in ("ACTIVE", "DENIED"):
        base = base.where(inv.status == status_filter)

    if ip_q:
        base = base.where(inv.ip == ip_q.strip())

    if port_q:
        pq = str(port_q).strip()
        try:
            base = base.where(inv.port == int(pq))
        except Exception:
            pass

    if owner_q:
        oq = owner_q.strip()
        if oq:
            base = base.where(func.lower(inv.owner) == func.lower(oq))

    if operator_q:
        opq = operator_q.strip()
        if opq:
            base = base.where(func.lower(inv.operator) == func.lower(opq))

    if comment_q:
        cq = comment_q.strip()
        if cq:
            base = base.where(inv.comment.ilike(f"%{cq}%"))

    return db.execute(base.order_by(inv.ip.asc(), inv.port.asc())).scalars().all()


def query_inventory(

    db: Session,
    start_dt: datetime,
    end_dt: datetime,
    firewall_blocked: str | None,
):
    """Results page source: inventory items whose latest_seen_at is within [start_dt, end_dt).
    (Open-only inventory is implied because inventory tracks open ports; but keep guard for safety.)
    """
    inv = models.PortInventory
    base = (
        select(inv)
        .where(inv.latest_seen_at >= start_dt)
        .where(inv.latest_seen_at < end_dt)
    )
    if firewall_blocked in ("Y", "N"):
        base = base.where(inv.firewall_blocked == firewall_blocked)
    return db.execute(base.order_by(inv.latest_seen_at.asc(), inv.ip.asc(), inv.port.asc())).scalars().all()


def list_assets(db: Session):
    inv = models.PortInventory

    ip_sub = (
        select(inv.ip, func.max(inv.latest_seen_at).label("last_seen_at"))
        .group_by(inv.ip)
        .subquery()
    )

    hostname_sq = (
        select(inv.hostname)
        .where(inv.ip == ip_sub.c.ip)
        .where(inv.hostname.is_not(None))
        .order_by(inv.latest_seen_at.desc())
        .limit(1)
        .scalar_subquery()
    )
    operator_sq = (
        select(inv.operator)
        .where(inv.ip == ip_sub.c.ip)
        .where(inv.operator.is_not(None))
        .order_by(inv.latest_seen_at.desc())
        .limit(1)
        .scalar_subquery()
    )
    owner_sq = (
        select(inv.owner)
        .where(inv.ip == ip_sub.c.ip)
        .where(inv.owner.is_not(None))
        .order_by(inv.latest_seen_at.desc())
        .limit(1)
        .scalar_subquery()
    )

    rows = db.execute(
        select(
            ip_sub.c.ip,
            ip_sub.c.last_seen_at,
            hostname_sq.label("hostname"),
            operator_sq.label("operator"),
            owner_sq.label("owner"),
        ).order_by(ip_sub.c.ip.asc())
    ).all()
    return rows





def update_asset_port(
    db: Session,
    inv_id: int,
    hostname: str | None,
    operator: str | None,
    owner: str | None,
    status: str | None,
    ticket: str | None,
    remediation_note: str | None,
    comment: str | None,
    reviewed: bool,
):
    inv = db.get(models.PortInventory, inv_id)
    if not inv:
        return None, None, None

    before = {
        "hostname": inv.hostname,
        "operator": getattr(inv, "operator", None),
        "owner": getattr(inv, "owner", None),
        "comment": inv.comment,
        "reviewed": inv.reviewed,
        "status": getattr(inv, "status", "ACTIVE"),
        "ticket": getattr(inv, "ticket", None),
        "remediation_note": getattr(inv, "remediation_note", None),
    }

    # normalize A안: strip only (no internal whitespace normalization)
    hn = (hostname or "").strip()
    op = (operator or "").strip()
    ow = (owner or "").strip()
    tk = (ticket or "").strip()
    cm = (comment or "").strip()
    rn = (remediation_note or "").strip()

    # IP-level fields propagate across all ports for that IP.
    if hostname is not None:
        db.execute(
            models.PortInventory.__table__.update()
            .where(models.PortInventory.ip == inv.ip)
            .values(hostname=hn or None)
        )
    if operator is not None:
        db.execute(
            models.PortInventory.__table__.update()
            .where(models.PortInventory.ip == inv.ip)
            .values(operator=op or None)
        )
    if owner is not None:
        db.execute(
            models.PortInventory.__table__.update()
            .where(models.PortInventory.ip == inv.ip)
            .values(owner=ow or None)
        )

    # Port-level fields should be consistent across FW profiles (same ip+port).
    old_status = (getattr(inv, "status", "ACTIVE") or "ACTIVE").strip().upper()

    # NOTE: When a port is INACTIVE (misses>=2), we prevent manual edits to Status/Reviewed
    # to avoid operator/admin mistakes. Inactive items are meant to re-enter via scanning.
    is_inactive = bool(getattr(inv, "inactive", False))

    port_vals: dict = {}

    # By default, allow reviewed updates when status isn't being changed.
    # When inactive, lock reviewed to avoid human error.
    if status is None and not is_inactive:
        port_vals["reviewed"] = bool(reviewed)

    if status is not None:
        # If inactive, ignore status changes (UI should also disable it)
        if not is_inactive:
            new_status = (status or "").strip().upper() or old_status
            port_vals["status"] = new_status

            # Human-error safe lifecycle rules:
            # - REMEDIATED / IGNORED: move to remediated view regardless of Reviewed; force Reviewed=True
            # - DENIED: stays in triage; force Reviewed=False (so it remains visibly "needs review")
            # - back to ACTIVE from REMEDIATED/DENIED/IGNORED/INACTIVE: force Reviewed=False and reset lifecycle
            if new_status in ("REMEDIATED", "IGNORED"):
                port_vals["remediation_at"] = datetime.utcnow()
                port_vals["reviewed"] = True
            elif new_status == "DENIED":
                port_vals["remediation_at"] = None
                port_vals["reviewed"] = False
            elif new_status == "ACTIVE":
                if old_status in ("REMEDIATED", "IGNORED", "INACTIVE", "DENIED") or is_inactive:
                    port_vals["reviewed"] = False
                    port_vals["inactive"] = False
                    port_vals["open_misses"] = 0
                    port_vals["remediation_at"] = None
                else:
                    # ACTIVE->ACTIVE: honor Reviewed selection
                    port_vals["reviewed"] = bool(reviewed)

            # If leaving remediate states, clear remediation timestamp.
            if old_status in ("REMEDIATED", "IGNORED") and new_status not in ("REMEDIATED", "IGNORED"):
                port_vals.setdefault("remediation_at", None)
    if ticket is not None:
        port_vals["ticket"] = tk or None
    if comment is not None:
        port_vals["comment"] = cm or None
    if remediation_note is not None:
        port_vals["remediation_note"] = rn or None

    db.execute(
        models.PortInventory.__table__.update()
        .where(models.PortInventory.ip == inv.ip)
        .where(models.PortInventory.port == inv.port)
        .values(**port_vals)
    )

    db.commit()
    db.refresh(inv)

    after = {
        "hostname": inv.hostname,
        "operator": getattr(inv, "operator", None),
        "owner": getattr(inv, "owner", None),
        "comment": inv.comment,
        "reviewed": inv.reviewed,
        "status": getattr(inv, "status", "ACTIVE"),
        "ticket": getattr(inv, "ticket", None),
        "remediation_note": getattr(inv, "remediation_note", None),
    }
    return inv, before, after



def list_users(db: Session):
    return db.execute(select(models.User).order_by(models.User.created_at.desc())).scalars().all()

def reset_user_password(db: Session, user_pk: int, new_hash: str):
    u = db.get(models.User, user_pk)
    if not u:
        return None
    u.password_hash = new_hash
    db.commit()
    return u


def reset_user_mfa(db: Session, user_pk: int):
    """Force MFA re-enrollment for a user (admin action)."""
    u = db.get(models.User, user_pk)
    if not u:
        return None
    u.mfa_enabled = False
    u.totp_secret = None
    db.commit()
    return u


def delete_user(db: Session, user_pk: int):
    """Hard-delete a user and detach related FK references safely.

    We preserve historical rows by NULL-ing nullable FKs (audit_logs.user_id, scan_runs.executed_by)
    and removing non-nullable dependent rows (sessions, preauth_sessions).

    Returns:
        dict with deletion stats, or None if user not found.

    Raises:
        ValueError if attempting to delete the last admin.
    """
    tgt = db.get(models.User, user_pk)
    if not tgt:
        return None

    if (tgt.role or "").lower() == "admin":
        admin_cnt = db.execute(
            select(func.count()).select_from(models.User).where(models.User.role == "admin")
        ).scalar_one()
        if admin_cnt <= 1:
            raise ValueError("Cannot delete the last admin")

    # Revoke + delete sessions / preauth sessions (non-nullable FK)
    db.execute(update(models.Session).where(models.Session.user_id == tgt.id).values(revoked=True))
    res_sess = db.execute(models.Session.__table__.delete().where(models.Session.user_id == tgt.id))
    res_pre = db.execute(models.PreAuthSession.__table__.delete().where(models.PreAuthSession.user_id == tgt.id))

    # Detach nullable references
    res_runs = db.execute(
        update(models.ScanRun).where(models.ScanRun.executed_by == tgt.id).values(executed_by=None)
    )
    res_aud = db.execute(
        update(models.AuditLog).where(models.AuditLog.user_id == tgt.id).values(user_id=None)
    )

    user_key = tgt.user_id
    db.delete(tgt)
    db.commit()

    return {
        "user_id": user_key,
        "sessions_deleted": int(getattr(res_sess, "rowcount", 0) or 0),
        "preauth_deleted": int(getattr(res_pre, "rowcount", 0) or 0),
        "scan_runs_detached": int(getattr(res_runs, "rowcount", 0) or 0),
        "audit_detached": int(getattr(res_aud, "rowcount", 0) or 0),
    }