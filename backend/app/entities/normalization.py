"""Pure normalization helpers; no entity indexing or alert correlation."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_FLOOR
import ipaddress
import ntpath
import re
from urllib.parse import urlsplit, urlunsplit
from zoneinfo import ZoneInfo

from app.utils.stable_id import nfc, utc_text


def text(value):
    if value is None or value == "":
        return None
    if type(value) not in (str, int):
        raise ValueError("invalid_text")
    return nfc(str(value))


def integer(value, *, minimum=0, maximum=None):
    if type(value) is str and re.fullmatch(r"[0-9]+", value):
        value = int(value)
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError("invalid_integer")
    return value


def ip(value):
    if text(value) is None:
        return None
    try:
        if type(value) is not str or "%" in value:
            raise ValueError("IP scope belongs in deployment settings")
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("invalid_ip") from exc


def hostname(value, aliases=None):
    value = text(value)
    if value is None:
        return None
    value = value.lower().rstrip(".")
    if not value:
        raise ValueError("invalid_hostname")
    return (aliases or {}).get(value, value)


def url(value):
    value = text(value)
    if value is None:
        return None
    parts = urlsplit(value)
    if not parts.netloc:
        if not parts.scheme:
            # urlsplit strips leading slashes from authority-less references
            # such as // and ///path. Preserve the observed request path/query;
            # only fragments are removed, as required by the URL contract.
            return value.split("#", 1)[0]
        return urlunsplit((parts.scheme.lower(), "", parts.path, parts.query, ""))
    host = parts.hostname
    if not host:
        raise ValueError("invalid_url")
    host = host.lower()
    if ":" in host:
        host = "[" + host + "]"
    port = parts.port  # Reject malformed or out-of-range ports.
    authority = host
    if port is not None and (parts.scheme.lower(), port) not in (("http", 80), ("https", 443)):
        authority += ":" + str(port)
    if "@" in parts.netloc:
        authority = parts.netloc.rsplit("@", 1)[0] + "@" + authority
    return urlunsplit((parts.scheme.lower(), authority, parts.path, parts.query, ""))


def file_path(value, os_type=None):
    value = text(value)
    if value is not None and os_type == "windows":
        return ntpath.normcase(value)
    return value


def timestamp(value, *, source_timezone=None, epoch_unit=None):
    if epoch_unit is not None:
        if epoch_unit not in ("seconds", "milliseconds", "microseconds"):
            raise ValueError("invalid_epoch_unit")
        if type(value) not in (int, float) or not Decimal(str(value)).is_finite():
            raise ValueError("invalid_timestamp")
        factor = {"seconds": 1000000, "milliseconds": 1000, "microseconds": 1}[epoch_unit]
        microseconds = int((Decimal(str(value)) * factor).to_integral_value(rounding=ROUND_FLOOR))
        return utc_text(datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds))
    if type(value) is not str:
        raise ValueError("invalid_timestamp")
    # Common vendor ISO offset spelling +0000 is equivalent to +00:00.
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
    if re.search(r"(?:Z|[+-]\d{2}:\d{2})$", value):
        return utc_text(value)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?", value):
        raise ValueError("invalid_timestamp")
    if source_timezone is None:
        raise ValueError("missing_timezone")
    dt = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", value))
    zone = timezone.utc if source_timezone == "UTC" else ZoneInfo(source_timezone)
    candidates = set()
    for fold in (0, 1):
        aware = dt.replace(tzinfo=zone, fold=fold)
        if aware.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None) == dt:
            candidates.add(utc_text(aware))
    if len(candidates) != 1:
        raise ValueError("ambiguous_or_nonexistent_timestamp")
    return candidates.pop()
