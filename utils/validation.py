"""Validation of uploaded event-log CSVs. Uploaded data is untrusted input.

validate_dataframe() never modifies the original file. It returns a cleaned,
typed COPY plus a report describing every problem found.
"""
import ipaddress
import re

import pandas as pd

REQUIRED_COLUMNS = ["timestamp", "username", "source_ip", "event_type",
                    "login_status", "failed_attempt_count"]
OPTIONAL_COLUMNS = ["label", "bytes_transferred"]
VALID_LOGIN_STATUS = {"success", "failed", "not_applicable"}
VALID_LABELS = {"normal", "suspicious"}
MAX_ISSUES_SHOWN = 50

TEMPLATE_CSV = (
    ",".join(REQUIRED_COLUMNS + OPTIONAL_COLUMNS) + "\n"
    "2025-03-03 09:15:02,alice,192.168.1.10,login,success,0,normal,0\n"
    "2025-03-03 09:16:40,alice,192.168.1.10,file_access,not_applicable,0,normal,8200\n"
)

_USER_RE = re.compile(r"^[A-Za-z0-9_.@\-]{1,64}$")
_EVENT_RE = re.compile(r"^[a-z0-9_]{1,50}$")


def sanitize_cell(value):
    """Neutralise CSV formula injection for any value written to an export."""
    s = str(value)
    return "'" + s if s and s[0] in ("=", "+", "-", "@", "\t", "\r") else s


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_dataframe(raw):
    """Return (clean_df or None, report dict)."""
    report = {"errors": [], "warnings": [], "issues": [], "rows_total": int(len(raw)),
              "rows_valid": 0, "rows_invalid": 0, "has_labels": False,
              "label_counts": {}, "columns_found": []}
    df = raw.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    report["columns_found"] = list(df.columns)

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        report["errors"].append("Missing required column(s): " + ", ".join(missing))
        return None, report
    if df.empty:
        report["errors"].append("The file contains a header but no data rows.")
        return None, report

    for c in df.columns:
        df[c] = df[c].astype(str).str.strip()
    reasons = {i: [] for i in df.index}

    def flag(mask, msg):
        for i in df.index[mask]:
            reasons[i].append(msg)

    ts = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    flag(ts.isna(), "invalid timestamp")

    flag(~df["username"].str.match(_USER_RE), "invalid username")
    df["event_type"] = df["event_type"].str.lower().str.replace(r"[\s\-]+", "_", regex=True)
    flag(~df["event_type"].str.match(_EVENT_RE), "invalid event_type")

    ip_ok = {v: _valid_ip(v) for v in df["source_ip"].unique()}
    flag(~df["source_ip"].map(ip_ok), "invalid source_ip")

    df["login_status"] = df["login_status"].str.lower()
    blank = df["login_status"] == ""
    if blank.any():
        report["warnings"].append(f"{int(blank.sum())} blank login_status value(s) treated as 'not_applicable'.")
        df.loc[blank, "login_status"] = "not_applicable"
    flag(~df["login_status"].isin(VALID_LOGIN_STATUS), "invalid login_status")

    fac = pd.to_numeric(df["failed_attempt_count"].replace("", "0"), errors="coerce")
    nblank = df["failed_attempt_count"] == ""
    if nblank.any():
        report["warnings"].append(f"{int(nblank.sum())} blank failed_attempt_count value(s) treated as 0.")
    flag(fac.isna() | (fac < 0) | (fac > 10000) | (fac % 1 != 0), "invalid failed_attempt_count")

    if "label" in df.columns:
        df["label"] = df["label"].str.lower()
        flag(~df["label"].isin(VALID_LABELS | {""}), "invalid label")
    if "bytes_transferred" in df.columns:
        b = pd.to_numeric(df["bytes_transferred"].replace("", pd.NA), errors="coerce")
        flag((df["bytes_transferred"] != "") & (b.isna() | (b < 0)), "invalid bytes_transferred")

    bad = pd.Series({i: bool(r) for i, r in reasons.items()})
    report["rows_invalid"] = int(bad.sum())
    report["rows_valid"] = int((~bad).sum())
    for i in df.index[bad][:MAX_ISSUES_SHOWN]:
        report["issues"].append({"row": int(i) + 2, "problems": "; ".join(reasons[i])})  # +2: header + 1-based
    if report["rows_invalid"] > MAX_ISSUES_SHOWN:
        report["warnings"].append(f"Only the first {MAX_ISSUES_SHOWN} invalid rows are listed.")
    if report["rows_valid"] == 0:
        report["errors"].append("No valid rows remain after validation.")
        return None, report

    clean = pd.DataFrame({
        "source_row": (df.index + 2),
        "timestamp": ts, "username": df["username"], "source_ip": df["source_ip"],
        "event_type": df["event_type"], "login_status": df["login_status"],
        "failed_attempt_count": fac.fillna(0).astype(int),
    })
    clean["label"] = df["label"] if "label" in df.columns else ""
    clean["bytes_transferred"] = (pd.to_numeric(df["bytes_transferred"].replace("", pd.NA), errors="coerce")
                                  if "bytes_transferred" in df.columns else float("nan"))
    clean = clean[~bad].sort_values("timestamp").reset_index(drop=True)

    dups = int(clean.duplicated(subset=REQUIRED_COLUMNS[:5]).sum())
    if dups:
        report["warnings"].append(f"{dups} duplicate event row(s) detected (kept, not removed).")

    counts = clean["label"].value_counts().to_dict()
    report["label_counts"] = {k: int(v) for k, v in counts.items() if k}
    report["has_labels"] = all(report["label_counts"].get(k, 0) > 0 for k in VALID_LABELS)
    if not report["has_labels"]:
        report["warnings"].append("No usable labels (need both 'normal' and 'suspicious'): "
                                  "supervised classification will be unavailable; unsupervised methods still work.")
    return clean, report
