from __future__ import annotations
from datetime import datetime
from sqlalchemy import String, Integer, DateTime, Boolean, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    username: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(200))
    department: Mapped[str] = mapped_column(String(100))
    phone_number: Mapped[str] = mapped_column(String(50))
    role: Mapped[str] = mapped_column(String(20), default="operator")  # operator/admin

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # security / account policy
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    user = relationship("User")

class PreAuthSession(Base):
    __tablename__ = "preauth_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    user = relationship("User")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(60), index=True)
    object_type: Mapped[str] = mapped_column(String(60))
    object_key: Mapped[str] = mapped_column(String(200))
    before: Mapped[str | None] = mapped_column(Text, nullable=True)
    after: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(60), nullable=True)
    user = relationship("User")

class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    xml_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scan_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="RUNNING")
    firewall_blocked: Mapped[str] = mapped_column(String(1), default="N")
    target_spec: Mapped[str] = mapped_column(Text)
    ports_spec: Mapped[str] = mapped_column(String(100))
    scan_type: Mapped[str] = mapped_column(String(10), default='tcp')
    extra_args: Mapped[str] = mapped_column(Text, default="")
    xml_path: Mapped[str] = mapped_column(Text)
    log_path: Mapped[str] = mapped_column(Text)
    executed_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    user = relationship("User")

class PortInventory(Base):
    __tablename__ = "port_inventory"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    firewall_blocked: Mapped[str] = mapped_column(String(1), default="N", index=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    latest_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    state_latest: Mapped[str] = mapped_column(String(30))
    service_latest: Mapped[str | None] = mapped_column(String(80), nullable=True)

    hostname: Mapped[str | None] = mapped_column(String(20), nullable=True)
    operator: Mapped[str | None] = mapped_column(String(60), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(60), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # lifecycle / remediation
    open_misses: Mapped[int] = mapped_column(Integer, default=0)
    inactive: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", index=True)  # ACTIVE/REMEDIATED/DENIED/IGNORED
    ticket: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    remediation_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    remediation_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("ip", "port", "firewall_blocked", name="uq_port_inventory_key"),
    )

class RunOpenPort(Base):
    __tablename__ = "run_open_ports"
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    port: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_blocked: Mapped[str] = mapped_column(String(1), primary_key=True, default="N")
    scan_run = relationship("ScanRun")


class ScanRunPortScope(Base):
    __tablename__ = "scan_run_port_scopes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")  # tcp/udp
    scope_kind: Mapped[str] = mapped_column(String(20), default="explicit")  # explicit/top_ports/unknown
    raw_spec: Mapped[str | None] = mapped_column(Text, nullable=True)
    top_ports: Mapped[int | None] = mapped_column(Integer, nullable=True)

    scan_run = relationship("ScanRun")
    ranges = relationship("ScanRunPortRange", cascade="all, delete-orphan", back_populates="scope")

    __table_args__ = (
        UniqueConstraint("run_id", "proto", name="uq_run_proto_scope"),
    )

class ScanRunPortRange(Base):
    __tablename__ = "scan_run_port_ranges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[int] = mapped_column(ForeignKey("scan_run_port_scopes.id"), index=True)
    port_start: Mapped[int] = mapped_column(Integer)
    port_end: Mapped[int] = mapped_column(Integer)

    scope = relationship("ScanRunPortScope", back_populates="ranges")

class ScanRunHost(Base):
    __tablename__ = "scan_run_hosts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    is_up: Mapped[bool] = mapped_column(Boolean, default=True)

    scan_run = relationship("ScanRun")

    __table_args__ = (
        UniqueConstraint("run_id", "ip", name="uq_run_ip"),
    )


class PortEvent(Base):

    __tablename__ = "port_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_time: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    ip: Mapped[str] = mapped_column(String(64), index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    firewall_blocked: Mapped[str] = mapped_column(String(1), default="N", index=True)

    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(30), index=True)  # FIRST_SEEN / STATE_CHANGED

    prev_state: Mapped[str | None] = mapped_column(String(30), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(30), nullable=True)
    prev_service: Mapped[str | None] = mapped_column(String(80), nullable=True)
    new_service: Mapped[str | None] = mapped_column(String(80), nullable=True)

    scan_run = relationship("ScanRun")
