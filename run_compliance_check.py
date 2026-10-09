"""Main program: load data -> run checks -> write reports -> build and open the dashboard.

Usage (from inside this folder):
    python run_compliance_check.py                  run with sample_data/accounts.csv
    python run_compliance_check.py --regenerate     make new sample data first
    python run_compliance_check.py --regenerate --seed 11
    python run_compliance_check.py --data my_export.csv
    python run_compliance_check.py --no-open        do not open the browser
"""
import argparse
import webbrowser
from datetime import date
from pathlib import Path

import config
import data_source
import checks
import report

HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description="Access Control continuous compliance checker")
    p.add_argument("--data", default=str(HERE / "sample_data" / "accounts.csv"))
    p.add_argument("--regenerate", action="store_true", help="create new sample data")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--no-open", action="store_true")
    args = p.parse_args()

    as_of = date.today()
    data_path = Path(args.data)
    if args.regenerate or not data_path.exists():
        data_path.parent.mkdir(exist_ok=True)
        data_source.generate_sample_csv(data_path, as_of, seed=args.seed)
        print(f"Created sample data: {data_path}")

    accounts = data_source.load_accounts(data_path, as_of)
    results = checks.run_all(accounts, config.CONTROLS, config.THRESHOLDS)

    print(f"\nAccess Control compliance check | data: {data_path.name} | date: {as_of}\n")
    for r in results:
        print(f"{r['id']}  {r['status']:5}  {r['compliance_pct']:5.1f}%  "
              f"({r['non_compliant']} of {r['in_scope']} non-compliant)  {r['requirement_text']}")

    out = HERE / "output"
    report.write_outputs(results, out)
    dash = out / "dashboard.html"
    report.build_dashboard(HERE / "dashboard_template.html", dash, accounts, config.CONTROLS,
                           config.THRESHOLDS, as_of, data_path.name)
    print(f"\nWrote reports and dashboard to: {out}")
    if not args.no_open:
        webbrowser.open(dash.as_uri())


if __name__ == "__main__":
    main()
