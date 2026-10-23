"""Generate the SYNTHETIC sample dataset (fixed seed => reproducible).
All usernames and IPs are fictional; external IPs use RFC 5737 documentation ranges."""
from pathlib import Path

import numpy as np
import pandas as pd

OUT = Path(__file__).resolve().parent / "sample_evidence.csv"


def main():
    rng = np.random.default_rng(42)
    users = ["admin", "alice", "bob", "carol", "dave", "erin", "frank", "grace",
             "heidi", "rkumar", "mchen", "priya"]
    ip_of = {u: f"192.168.1.{10 + i}" for i, u in enumerate(users)}
    start = pd.Timestamp("2025-03-03")
    rows = []

    def add(t, u, ip, ev, status, fails, label, nbytes=0):
        rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), u, ip, ev, status, int(fails), label, int(nbytes)))

    # normal behaviour: business-hours sessions Mon-Fri, light weekend use
    for day in range(7):
        d = start + pd.Timedelta(days=day)
        for u in users:
            for _ in range(int(rng.integers(2, 6)) if day < 5 else int(rng.integers(0, 2))):
                t = d + pd.Timedelta(hours=int(np.clip(rng.normal(13, 3), 7, 20)),
                                     minutes=int(rng.integers(0, 60)), seconds=int(rng.integers(0, 60)))
                ip = ip_of[u]
                if rng.random() < 0.06:  # honest typo before logging in
                    add(t, u, ip, "login", "failed", 1, "normal")
                    t += pd.Timedelta(seconds=30)
                add(t, u, ip, "login", "success", 0, "normal")
                for _ in range(int(rng.integers(2, 9))):
                    t += pd.Timedelta(minutes=int(rng.integers(1, 25)))
                    ev = rng.choice(["file_access", "file_download", "config_change", "password_change"],
                                    p=[0.62, 0.26, 0.09, 0.03])
                    nb = (rng.lognormal(9, 0.8) if ev == "file_access"
                          else rng.lognormal(12, 0.8) if ev == "file_download" else 0)
                    add(t, u, ip, ev, "not_applicable", 0, "normal", nb)
                add(t + pd.Timedelta(minutes=int(rng.integers(1, 15))), u, ip, "logout", "not_applicable", 0, "normal")

    # scenario 1: brute force against 'admin' from an external IP
    t = start + pd.Timedelta(days=1, hours=2, minutes=14)
    ip = "203.0.113.45"
    for n in range(1, 41):
        add(t, "admin", ip, "login", "failed", n, "suspicious")
        t += pd.Timedelta(seconds=int(rng.integers(4, 9)))
    add(t, "admin", ip, "login", "success", 40, "suspicious")
    add(t + pd.Timedelta(minutes=2), "admin", ip, "privilege_change", "not_applicable", 0, "suspicious")
    add(t + pd.Timedelta(minutes=5), "admin", ip, "file_download", "not_applicable", 0, "suspicious", rng.lognormal(15, 0.3))

    # scenario 2: password spraying (few attempts across many accounts)
    t = start + pd.Timedelta(days=3, hours=3, minutes=30)
    for u in users[:8]:
        for n in (1, 2):
            add(t, u, "198.51.100.23", "login", "failed", n, "suspicious")
            t += pd.Timedelta(seconds=int(rng.integers(20, 50)))

    # scenario 3: bulk data download by an insider late at night
    t = start + pd.Timedelta(days=4, hours=23, minutes=40)
    for _ in range(25):
        add(t, "rkumar", ip_of["rkumar"], "file_download", "not_applicable", 0, "suspicious", rng.lognormal(15.5, 0.4))
        t += pd.Timedelta(seconds=int(rng.integers(15, 30)))

    # scenario 4: off-hours logins from an unfamiliar IP
    for k in range(3):
        t = start + pd.Timedelta(days=2 + k, hours=3, minutes=int(rng.integers(0, 50)))
        add(t, "mchen", "198.51.100.77", "login", "success", 0, "suspicious")
        add(t + pd.Timedelta(minutes=3), "mchen", "198.51.100.77", "config_change", "not_applicable", 0, "suspicious")

    df = pd.DataFrame(rows, columns=["timestamp", "username", "source_ip", "event_type", "login_status",
                                     "failed_attempt_count", "label", "bytes_transferred"])
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    df.to_csv(OUT, index=False)
    print(f"Wrote {len(df)} synthetic events ({(df.label == 'suspicious').sum()} suspicious) to {OUT}")


if __name__ == "__main__":
    main()
