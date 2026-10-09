"""Writes the CSV files, results.json and the HTML dashboard."""
import csv
import json
from pathlib import Path


def write_outputs(results, out_dir):
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    with open(out / "compliance_report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["control", "requirement", "mapping", "in_scope", "non_compliant", "compliance_pct", "status"])
        for r in results:
            w.writerow([r["id"], r["requirement_text"], "; ".join(r["mapping"]), r["in_scope"],
                        r["non_compliant"], r["compliance_pct"], r["status"]])
    with open(out / "noncompliant_accounts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["control", "account", "finding", "action"])
        for r in results:
            for e in r["exceptions"]:
                w.writerow([r["id"], e["account"], e["finding"], "Ticket to owner"])
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


def build_dashboard(template_path, out_path, accounts, controls, thresholds, as_of, source_name):
    data = {"as_of": as_of.isoformat(), "source": source_name, "thresholds": thresholds,
            "controls": controls, "accounts": accounts}
    blob = json.dumps(data).replace("</", "<\\/")
    html = Path(template_path).read_text(encoding="utf-8").replace("/*__DATA__*/null", blob)
    Path(out_path).write_text(html, encoding="utf-8")
