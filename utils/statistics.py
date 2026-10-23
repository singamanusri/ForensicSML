
import pandas as pd


def analyze_evidence(csv_path):
    df = pd.read_csv(csv_path)

    total_events = len(df)

    login_status = (
        df["login_status"].astype(str).str.strip().str.lower()
        if "login_status" in df.columns
        else pd.Series(dtype=str)
    )

    failed_logins = int(
        login_status.isin(["failed", "failure", "fail", "unsuccessful"]).sum()
    )

    event_counts = (
        df["event_type"].fillna("Unknown").astype(str).value_counts().to_dict()
        if "event_type" in df.columns
        else {}
    )

    label_counts = (
        df["label"].fillna("Unknown").astype(str).value_counts().to_dict()
        if "label" in df.columns
        else {}
    )

    hourly_counts = {}
    if "timestamp" in df.columns:
        timestamps = pd.to_datetime(df["timestamp"], errors="coerce")
        hours = timestamps.dt.hour.dropna().astype(int)
        hourly_counts = {
            str(int(hour)): int(count)
            for hour, count in hours.value_counts().sort_index().items()
        }

    ip_counts = (
        df["source_ip"].fillna("Unknown").astype(str).value_counts().head(10).to_dict()
        if "source_ip" in df.columns
        else {}
    )

    failed_attempts = pd.to_numeric(
        df.get("failed_attempt_count", pd.Series(dtype=float)),
        errors="coerce"
    ).dropna()

    bytes_transferred = pd.to_numeric(
        df.get("bytes_transferred", pd.Series(dtype=float)),
        errors="coerce"
    ).dropna()

    return {
        "total_events": int(total_events),
        "failed_logins": failed_logins,
        "failed_login_percentage": round(
            failed_logins / total_events * 100, 2
        ) if total_events else 0,
        "event_counts": event_counts,
        "label_counts": label_counts,
        "hourly_counts": hourly_counts,
        "top_ips": ip_counts,
        "failed_attempt_mean": round(float(failed_attempts.mean()), 2)
        if not failed_attempts.empty else 0,
        "failed_attempt_max": int(failed_attempts.max())
        if not failed_attempts.empty else 0,
        "bytes_transferred_mean": round(float(bytes_transferred.mean()), 2)
        if not bytes_transferred.empty else 0,
        "bytes_transferred_max": int(bytes_transferred.max())
        if not bytes_transferred.empty else 0,
    }

