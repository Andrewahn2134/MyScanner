from __future__ import annotations
import os, subprocess, threading, shlex
from dataclasses import dataclass
import xml.etree.ElementTree as ET
from typing import Optional, Iterable

LOG_DIR = os.environ.get("LOG_DIR", "/var/MyScanner/log")
DEFAULT_TCP_ARGS = os.environ.get("DEFAULT_TCP_ARGS", "-Pn -T4 -vv")
DEFAULT_UDP_ARGS = os.environ.get("DEFAULT_UDP_ARGS", "-Pn -sU -vv")

@dataclass
class RunningProc:
    popen: subprocess.Popen
    xml_path: str
    log_path: str
    cmd: list[str]
    stop_flag: bool = False

RUNNING: dict[str, RunningProc] = {}

def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)

def build_paths(xml_id: str):
    ensure_log_dir()
    return os.path.join(LOG_DIR, f"{xml_id}.xml"), os.path.join(LOG_DIR, f"{xml_id}.log")

def build_cmd(xml_path: str, targets: list[str], ports_spec: str | None, extra_args: list[str] | None,
              scan_type: str = "tcp", top_ports: int | None = None) -> list[str]:
    base = DEFAULT_TCP_ARGS if scan_type.lower() != "udp" else DEFAULT_UDP_ARGS
    cmd = ["nmap"] + shlex.split(base)

    if top_ports:
        cmd += ["--top-ports", str(int(top_ports))]
    else:
        if not ports_spec:
            raise ValueError("ports_spec required when top_ports is not set")
        cmd += ["-p", ports_spec]

    if extra_args:
        cmd += list(extra_args)

    # Output XML for parsing
    cmd += ["-oX", xml_path]

    # Targets at the end
    cmd += targets
    return cmd

def start_scan(xml_id: str, targets: list[str], ports_spec: str | None, extra_args: list[str] | None,
               scan_type: str = "tcp", top_ports: int | None = None) -> RunningProc:
    xml_path, log_path = build_paths(xml_id)
    cmd = build_cmd(xml_path, targets, ports_spec, extra_args, scan_type=scan_type, top_ports=top_ports)

    # Ensure clean old files
    for p in (xml_path, log_path):
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass

    logf = open(log_path, "w", encoding="utf-8", buffering=1)
    pop = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    rp = RunningProc(popen=pop, xml_path=xml_path, log_path=log_path, cmd=cmd)
    RUNNING[xml_id] = rp

    def _pump():
        try:
            if pop.stdout:
                for line in pop.stdout:
                    logf.write(line)
        finally:
            logf.close()

    threading.Thread(target=_pump, daemon=True).start()
    return rp

def stop_scan(xml_id: str) -> bool:
    rp = RUNNING.get(xml_id)
    if not rp:
        return False
    try:
        rp.stop_flag = True
        rp.popen.terminate()
        try:
            rp.popen.wait(timeout=5)
        except Exception:
            rp.popen.kill()
    finally:
        # Keep artifacts (xml/log) so an admin can still ingest results after a manual stop.
        # Artifacts are cleaned up after a successful ingest.
        RUNNING.pop(xml_id, None)
    return True

def scan_finished(xml_id: str) -> bool:
    rp = RUNNING.get(xml_id)
    if not rp:
        return True
    return rp.popen.poll() is not None

def read_log_tail(xml_id: str, max_bytes: int = 15000) -> str:
    rp = RUNNING.get(xml_id)
    _, log_path = build_paths(xml_id)
    try:
        p = rp.log_path if rp else log_path
        if not os.path.exists(p):
            return ""
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return f.read().decode("utf-8", errors="replace")
    except Exception:
        return ""

def get_cmd(xml_id: str) -> str | None:
    rp = RUNNING.get(xml_id)
    if not rp:
        return None
    return " ".join(shlex.quote(x) for x in rp.cmd)

def parse_nmap_xml(xml_path: str) -> tuple[list[dict], list[dict]]:
    """Parse Nmap -oX output.

    Returns:
      observed: list of port observations (ip, port, proto, state, service)
      hosts: list of hosts seen in XML (ip, is_up)
    """
    observed: list[dict] = []
    hosts: list[dict] = []
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        if not ip:
            continue

        st = host.find("status")
        is_up = True
        if st is not None and st.get("state"):
            is_up = (st.get("state") == "up")
        hosts.append({"ip": ip, "is_up": is_up})

        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            proto = p.get("protocol")
            portid = p.get("portid")
            if not portid:
                continue
            st = p.find("state")
            state = st.get("state") if st is not None else None
            svc = p.find("service")
            service = svc.get("name") if svc is not None else None
            observed.append({
                "ip": ip,
                "port": int(portid),
                "proto": proto or "tcp",
                "state": state or "",
                "service": service or "",
            })
    return observed, hosts
