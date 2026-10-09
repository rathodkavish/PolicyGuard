"""The automated checks. Each check returns (accounts_in_scope, list_of_(account, finding))."""


def check_r1(accounts, t):                      # Admin MFA
    scope = [a for a in accounts if a["is_admin"] and a["enabled"]]
    return len(scope), [(a["account"], "No MFA") for a in scope if not a["mfa"]]


def check_r2(accounts, t):                      # Access reviews
    scope = [a for a in accounts if a["is_admin"] and a["enabled"]]
    return len(scope), [(a["account"], f"Last review {a['review_days']} days ago")
                        for a in scope if a["review_days"] > t["review_days"]]


def check_r3(accounts, t):                      # Leaver removal
    scope = [a for a in accounts if a["left"]]
    bad = []
    for a in scope:
        h = a["disabled_after_hours"]
        if a["enabled"]:
            bad.append((a["account"], "Still enabled"))
        elif h is None:
            bad.append((a["account"], "No disable time recorded"))
        elif h > t["leaver_hours"]:
            bad.append((a["account"], f"Disabled after {h} h"))
    return len(scope), bad


def check_r4(accounts, t):                      # Dormant accounts
    scope = [a for a in accounts if a["enabled"]]
    return len(scope), [(a["account"], f"Last login {a['login_days']} days ago")
                        for a in scope if a["login_days"] > t["dormant_days"]]


CHECKS = {"R1": check_r1, "R2": check_r2, "R3": check_r3, "R4": check_r4}


def status(pct, amber):
    return "GREEN" if pct >= 100 else ("AMBER" if pct >= amber else "RED")


def run_all(accounts, controls, thresholds):
    results = []
    for c in controls:
        total, bad = CHECKS[c["id"]](accounts, thresholds)
        pct = 100.0 * (total - len(bad)) / total if total else 100.0
        results.append({**c, "requirement_text": c["requirement"].format(**thresholds),
                        "in_scope": total, "non_compliant": len(bad), "compliance_pct": round(pct, 1),
                        "status": status(pct, c["amber"]),
                        "exceptions": [{"account": a, "finding": f} for a, f in bad]})
    return results
