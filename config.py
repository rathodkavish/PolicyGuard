"""Settings for the Access Control compliance checker.

Edit THRESHOLDS to change the policy numbers. Edit CONTROLS to change policy text,
framework mapping, owners and so on. Everything else reads from here, so the console
report, the CSV files and the dashboard always agree.
"""

THRESHOLDS = {
    "review_days": 90,    # admin accounts must be reviewed at least this often
    "leaver_hours": 24,   # leavers must be disabled within this many hours
    "dormant_days": 45,   # enabled accounts with no login for longer than this are dormant
}

CONTROLS = [
    {"id": "R1", "title": "Admin MFA",
     "policy": "Privileged accounts must use multi-factor authentication.",
     "requirement": "100% of admin accounts have MFA enabled",
     "mapping": ["NIST IA-2(1)", "NIST AC-6", "ISO A.8.5", "ISO A.8.2"], "amber": 98,
     "check": "List enabled admin accounts that have no MFA method registered.",
     "source": "Identity provider, cloud IAM reports", "frequency": "Daily",
     "owner": "Identity and access team"},
    {"id": "R2", "title": "Access reviews",
     "policy": "Privileged access must be reviewed regularly.",
     "requirement": "100% of admin accounts reviewed in the last {review_days} days",
     "mapping": ["NIST AC-2", "ISO A.5.18"], "amber": 95,
     "check": "Compare each admin account's last review date with today.",
     "source": "Access review tool or ticket system", "frequency": "Weekly",
     "owner": "Security governance"},
    {"id": "R3", "title": "Leaver removal",
     "policy": "Access of leavers must be removed promptly.",
     "requirement": "100% of leavers disabled within {leaver_hours} hours",
     "mapping": ["NIST AC-2", "ISO A.5.16", "ISO A.5.18"], "amber": 95,
     "check": "Compare HR termination time with the account disable time.",
     "source": "HR system and identity provider", "frequency": "Daily",
     "owner": "IT operations with HR"},
    {"id": "R4", "title": "Dormant accounts",
     "policy": "Unused accounts must be disabled.",
     "requirement": "No enabled account without login for over {dormant_days} days",
     "mapping": ["NIST AC-2", "ISO A.5.18"], "amber": 95,
     "check": "Find enabled accounts whose last login is older than the limit.",
     "source": "Identity provider", "frequency": "Daily",
     "owner": "Identity and access team"},
]
