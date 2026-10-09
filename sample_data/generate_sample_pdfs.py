"""Generate sample policy PDF files for testing PolicyGuard document upload."""
from pathlib import Path
from fpdf import FPDF

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"
SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

class PolicyPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(31, 56, 100)
        self.cell(0, 10, "PolicyGuard - Enterprise Governance Standard", border=False, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 210, 225)
        self.set_line_width(0.5)
        self.line(10, 22, 200, 22)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(140, 150, 165)
        self.cell(0, 10, f"Confidential & Proprietary | Page {self.page_no()}", border=False, align="C")

def build_pdf(filename: str, metadata: dict, sections: list):
    pdf = PolicyPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # Document Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 12, metadata["Policy Name"], new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Metadata Box
    pdf.set_fill_color(245, 247, 250)
    pdf.set_draw_color(210, 220, 230)
    pdf.rect(10, pdf.get_y(), 190, 44, style="DF")
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(70, 80, 95)

    pdf.set_xy(14, pdf.get_y() + 3)
    pdf.cell(0, 6, f"Policy Name: {metadata['Policy Name']}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.cell(0, 6, f"Category: {metadata['Category']}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.cell(0, 6, f"Version: {metadata['Version']}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.cell(0, 6, f"Owner: {metadata['Owner']}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.cell(0, 6, f"Effective Date: {metadata['Effective Date']}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.cell(0, 6, f"Review Date: {metadata['Review Date']}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Sections
    for heading, paragraphs in sections:
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(31, 56, 100)
        pdf.cell(0, 8, heading, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(35, 45, 60)
        for p in paragraphs:
            pdf.multi_cell(0, 5.5, p)
            pdf.ln(2)
        pdf.ln(3)

    out_path = SAMPLE_DIR / filename
    pdf.output(str(out_path))
    print(f"Generated: {out_path}")
    return out_path

def main():
    # 1. Access Control Policy (Full match for R1-R4 continuous compliance checks)
    build_pdf(
        "sample_access_control_policy.pdf",
        {
            "Policy Name": "Enterprise Access Control & Identity Security Policy",
            "Version": "3.2",
            "Owner": "Identity and Access Management Governance Team",
            "Effective Date": "2026-01-01",
            "Review Date": "2026-12-31",
            "Category": "Access Control"
        },
        [
            ("1. Purpose & Strategic Scope", [
                "This policy establishes mandatory identity governance, authentication safeguards, and account lifecycle controls across all cloud platforms, infrastructure consoles, and corporate information systems.",
                "All internal employees, contractors, and administrative operators must strictly adhere to these controls to safeguard organizational assets."
            ]),
            ("2. Measurable Policy Directives", [
                "- Privileged accounts must use multi-factor authentication (MFA) prior to gaining access to critical environments.",
                "- Administrative access must be reviewed every 90 days by designated security governance custodians.",
                "- Terminated users must have access disabled within 24 hours of official HR separation notification.",
                "- Enabled accounts without activity for more than 45 days must be reviewed and remediated to prevent dormant credential exploitation."
            ]),
            ("3. Continuous Compliance & Enforcement", [
                "Adherence to these technical directives will be assessed continuously by automated telemetry checks. Violations are logged as risk findings and assigned to resource owners for mandatory remediation."
            ])
        ]
    )

    # 2. Authentication / Password Policy
    build_pdf(
        "sample_authentication_policy.pdf",
        {
            "Policy Name": "Global Authentication and Credential Security Policy",
            "Version": "2.1",
            "Owner": "Chief Information Security Officer (CISO)",
            "Effective Date": "2026-02-15",
            "Review Date": "2027-02-14",
            "Category": "Authentication / Password"
        },
        [
            ("1. Objective", [
                "This policy dictates identity verification, credential standards, and single sign-on (SSO) protocols for all authorized actors accessing organizational services."
            ]),
            ("2. Core Requirements", [
                "- Privileged accounts must use multi-factor authentication for interactive and programmatic console sessions.",
                "- Passwords must adhere to modern NIST SP 800-63B guidelines, prohibiting easily guessable phrases.",
                "- Single Sign-On (SSO) integration is required for all enterprise software-as-a-service applications."
            ]),
            ("3. Verification & Governance", [
                "Authentication telemetry shall be monitored continuously by security engineering."
            ])
        ]
    )

    # 3. Data Protection & Encryption Policy
    build_pdf(
        "sample_data_protection_policy.pdf",
        {
            "Policy Name": "Corporate Data Protection and Cryptographic Controls Policy",
            "Version": "1.8",
            "Owner": "Data Governance & Privacy Committee",
            "Effective Date": "2026-03-01",
            "Review Date": "2027-03-01",
            "Category": "Data Protection"
        },
        [
            ("1. Objective", [
                "This policy defines baseline cryptographic protections, data classification, and DLP requirements across all cloud storage repositories."
            ]),
            ("2. Encryption Standards", [
                "- Sensitive corporate and customer data must be encrypted using approved cryptographic standards such as AES-256 at rest.",
                "- All communications carrying confidential data across public networks must enforce cryptographic encryption in transit.",
                "- Data Loss Prevention (DLP) controls must be deployed across cloud assets and endpoints."
            ]),
            ("3. Auditing", [
                "Periodic validation of cryptographic keys and volume encryption state will be reviewed quarterly."
            ])
        ]
    )

    # 4. Logging and Monitoring Policy
    build_pdf(
        "sample_logging_monitoring_policy.pdf",
        {
            "Policy Name": "Security Telemetry and Audit Logging Standard",
            "Version": "4.0",
            "Owner": "Security Operations Center (SOC)",
            "Effective Date": "2026-01-10",
            "Review Date": "2027-01-10",
            "Category": "Logging and Monitoring"
        },
        [
            ("1. Objective", [
                "Ensures adequate audit trails are established and retained to support incident detection, investigation, and regulatory compliance."
            ]),
            ("2. Logging Directives", [
                "- Centralized audit logs must be enabled and retained for all security-relevant events across servers and network appliances.",
                "- Security audit logs must be retained for at least 365 days in tamper-resistant storage.",
                "- High-severity access anomalies and privilege escalations must alert the SOC in near real-time."
            ]),
            ("3. Compliance Monitoring", [
                "Automated probes will verify SIEM ingestion rates and archive retention compliance daily."
            ])
        ]
    )

if __name__ == "__main__":
    main()
