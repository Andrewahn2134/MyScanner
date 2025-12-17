import secrets
from datetime import datetime, timedelta
from passlib.context import CryptContext
import pyotp

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
COOKIE_NAME = "myscanner_session"
PREAUTH_COOKIE = "myscanner_preauth"
SESSION_TTL_HOURS = 2

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)

def validate_password_complexity(pw: str) -> str | None:
    """
    Enforce signup password policy:
      - length >= 8
      - at least 1 uppercase letter (A-Z)
      - at least 1 lowercase letter (a-z)
      - at least 1 digit (0-9)
      - at least 1 special character (non-alphanumeric)

    Returns:
      - None if valid
      - error message (Korean) if invalid
    """
    if pw is None:
        return "비밀번호를 입력해줘."
    if len(pw) < 8:
        return "비밀번호는 8자 이상이어야 해. (영문 대문자/소문자/숫자/특수문자 포함)"
    has_upper = any("A" <= c <= "Z" for c in pw)
    has_lower = any("a" <= c <= "z" for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(not c.isalnum() for c in pw)
    missing = []
    if not has_upper: missing.append("대문자")
    if not has_lower: missing.append("소문자")
    if not has_digit: missing.append("숫자")
    if not has_special: missing.append("특수문자")
    if missing:
        return "비밀번호 정책 미충족: " + ", ".join(missing) + "를 포함해줘. (8자 이상)"
    return None


def generate_temp_password(length: int = 12) -> str:
    """Generate a random password that satisfies validate_password_complexity()."""
    if length < 8:
        length = 8
    upp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    low = "abcdefghijklmnopqrstuvwxyz"
    dig = "0123456789"
    # keep to URL/HTML-safe-ish specials (still counts as special)
    spe = "!@#$%^&*()-_=+[]{};:,.?/"
    # ensure at least one from each category
    chars = [secrets.choice(upp), secrets.choice(low), secrets.choice(dig), secrets.choice(spe)]
    pool = upp + low + dig + spe
    for _ in range(max(0, length - len(chars))):
        chars.append(secrets.choice(pool))
    secrets.SystemRandom().shuffle(chars)
    pw = "".join(chars)
    # extremely defensive: regenerate if policy check fails
    if validate_password_complexity(pw) is not None:
        return generate_temp_password(length)
    return pw

def new_totp_secret() -> str:
    return pyotp.random_base32()

def totp_uri(user_id: str, secret: str, issuer: str = "MyScanner") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=user_id, issuer_name=issuer)

def verify_totp(secret: str, code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False

def new_session_id() -> str:
    return secrets.token_urlsafe(48)

def session_expiry() -> datetime:
    return datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)