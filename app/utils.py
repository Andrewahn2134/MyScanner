import re, ipaddress, shlex
from datetime import datetime
from zoneinfo import ZoneInfo

KST = ZoneInfo("Asia/Seoul")

def to_kst(dt: datetime | None) -> str:
    if not dt:
        return "-"
    return dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(KST).strftime("%Y-%m-%d %H:%M:%S")

_ip_re = re.compile(r"^[0-9a-fA-F\.:/,_\s-]+$")
_range_re = re.compile(r"^(?P<pfx>(?:\d{1,3}\.){3})(?P<start>\d{1,3})-(?P<end>\d{1,3})$")
MAX_RANGE_EXPANSION = 4096

def parse_targets(target_spec: str) -> list[str]:
    """Parse targets. Supports:
    - single IPs: 192.168.0.1
    - CIDR: 192.168.0.0/24
    - IPv4 last-octet range: 192.168.0.1-50 (expanded)
    - multiple separated by comma/space
    """
    s = (target_spec or "").strip()
    if not s:
        return []
    if not _ip_re.match(s):
        raise ValueError("Invalid characters in target")
    parts = re.split(r"[,_\s]+", s)
    raw = [p for p in parts if p]

    out: list[str] = []
    for t in raw:
        if "/" in t:
            ipaddress.ip_network(t, strict=False)
            out.append(t)
            continue

        m = _range_re.match(t)
        if m:
            pfx = m.group("pfx")
            start_o = int(m.group("start"))
            end_o = int(m.group("end"))
            if start_o < 0 or end_o < 0 or start_o > 255 or end_o > 255 or end_o < start_o:
                raise ValueError("Invalid IP range")
            count = (end_o - start_o) + 1
            if count > MAX_RANGE_EXPANSION:
                raise ValueError("Range too large")
            for i in range(start_o, end_o + 1):
                ipaddress.ip_address(pfx + str(i))
                out.append(pfx + str(i))
            continue

        ipaddress.ip_address(t)
        out.append(t)

    if len(out) > MAX_RANGE_EXPANSION:
        raise ValueError("Too many targets")
    return out


_ports_re = re.compile(r"^[0-9,\-]+$")

def validate_ports(ports_spec: str) -> str:
    p = (ports_spec or "").strip()
    if not p:
        raise ValueError("Ports required")
    if not _ports_re.match(p):
        raise ValueError("Invalid ports format. Use 22,80,443 or 1-1024")
    return p

def parse_allowed_targets(env_val: str):
    nets = []
    for part in (env_val or "").split(","):
        part = part.strip()
        if not part:
            continue
        nets.append(ipaddress.ip_network(part, strict=False))
    return nets

def target_allowed(targets: list[str], allowed_nets) -> bool:
    for t in targets:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            ok = any(net.subnet_of(a) or net == a for a in allowed_nets)
        else:
            ip = ipaddress.ip_address(t)
            ok = any(ip in a for a in allowed_nets)
        if not ok:
            return False
    return True

_extra_allowed_chars = re.compile(r"^[a-zA-Z0-9\s\-\._=:/]+$")

BLOCKED_TOKENS = [
    "-oX", "-oN", "-oG", "-oA", "--datadir", "--stylesheet", "--script", "--script-args",
    "--resume", "-iL", "--interactive",
]

ALLOWED_EXTRA_OPTS = {"--max-retries", "--host-timeout", "--min-rate"}
def sanitize_extra_args(extra: str) -> list[str]:
    """Return a safe, tokenized extra-args list (only allow a small whitelist)."""
    e = (extra or "").strip()
    if not e:
        return []
    # tokenize safely
    try:
        toks = shlex.split(e)
    except Exception:
        raise ValueError("Invalid extra args")
    out: list[str] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        # allow --opt=value forms
        if "=" in t:
            opt, val = t.split("=", 1)
            if opt not in ALLOWED_EXTRA_OPTS:
                raise ValueError(f"Option not allowed: {opt}")
            if not val:
                raise ValueError(f"Missing value for {opt}")
            out.append(f"{opt}={val}")
            i += 1
            continue
        if t in ALLOWED_EXTRA_OPTS:
            if i + 1 >= len(toks):
                raise ValueError(f"Missing value for {t}")
            val = toks[i + 1]
            if val.startswith("-"):
                raise ValueError(f"Missing value for {t}")
            out += [t, val]
            i += 2
            continue
        raise ValueError(f"Option not allowed: {t}")
    return out
