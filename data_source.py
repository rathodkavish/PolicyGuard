"""Where the account data comes from.

Right now it is a CSV file (sample_data/accounts.csv). To use real data, export the same
columns from your identity provider and HR system and point the program at that file.
"""
import csv
import random
from datetime import date, timedelta

FIELDS = ["account", "is_admin", "mfa_enabled", "last_review_date", "last_login_date",
          "enabled", "terminated_on", "disabled_after_hours"]


def generate_sample_csv(path, as_of, seed=7, n=60):
    """Write fake accounts so the project can be demonstrated without real data."""
    rnd = random.Random(seed)
    rows = []
    for i in range(1, n + 1):
        admin = i <= 15
        left = rnd.random() < 0.15
        enabled, term, hours = True, "", ""
        if left:
            term = (as_of - timedelta(days=rnd.randint(1, 20))).isoformat()
            hours = rnd.choice([2, 5, 10, 20, 20, 30, 50])
            enabled = rnd.random() < 0.2          # a few leavers are still enabled
        rows.append({
            "account": f"user{i:03d}", "is_admin": str(admin).upper(),
            "mfa_enabled": str(rnd.random() < (0.9 if admin else 0.7)).upper(),
            "last_review_date": (as_of - timedelta(days=rnd.randint(10, 130))).isoformat(),
            "last_login_date": (as_of - timedelta(days=rnd.randint(0, 70))).isoformat(),
            "enabled": str(enabled).upper(), "terminated_on": term, "disabled_after_hours": hours})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)


def _flag(value):
    return str(value).strip().upper() in ("TRUE", "YES", "1", "Y")


def _days_since(text, as_of):
    if not str(text).strip():
        return 9999                                 # missing date = treated as never
    return (as_of - date.fromisoformat(text.strip())).days


def load_accounts(path, as_of):
    """Read the CSV and convert dates into 'days ago' numbers relative to as_of."""
    accounts = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            hours = r["disabled_after_hours"].strip()
            accounts.append({
                "account": r["account"], "is_admin": _flag(r["is_admin"]), "mfa": _flag(r["mfa_enabled"]),
                "review_days": _days_since(r["last_review_date"], as_of),
                "login_days": _days_since(r["last_login_date"], as_of),
                "enabled": _flag(r["enabled"]), "left": bool(r["terminated_on"].strip()),
                "disabled_after_hours": int(hours) if hours else None})
    return accounts
