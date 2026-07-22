import os
import csv
from datetime import datetime
from collections import Counter
import pandas as pd
from scanner import scan_dataframe, assess_risk


def summarize(findings: list) -> dict:
    by_type = Counter(f["pii_type"] for f in findings)
    by_column = Counter(f["column"] for f in findings)
    return {
        "total": len(findings),
        "by_type": dict(by_type),
        "by_column": dict(by_column),
    }


def generate_csv_report(findings: list, output_path: str = "reports/pii_findings.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["row", "column", "pii_type", "value_masked"])
        writer.writeheader()
        writer.writerows(findings)
    print(f"CSV report written to {output_path}")


def generate_html_report(findings: list, risk: dict, output_path: str = "reports/pii_report.html"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    summary = summarize(findings)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    risk_colors = {
        "High": "#d32f2f",
        "Medium-High": "#f57c00",
        "Medium": "#fbc02d",
        "Low": "#388e3c",
    }
    banner_color = risk_colors.get(risk["risk_level"], "#757575")

    type_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in summary["by_type"].items()
    )
    column_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in summary["by_column"].items()
    )
    finding_rows = "".join(
        f"<tr><td>{f['row']}</td><td>{f['column']}</td><td>{f['pii_type']}</td><td>{f['value_masked']}</td></tr>"
        for f in findings
    )

    html = f"""
    <html>
    <head>
        <title>PII Risk Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            h1, h2 {{ color: #222; }}
            .banner {{
                background: {banner_color};
                color: white;
                padding: 20px;
                border-radius: 6px;
                margin-bottom: 20px;
            }}
            .banner h2 {{ margin: 0 0 8px 0; color: white; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; background: white; }}
            th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
            th {{ background-color: #333; color: white; }}
            .meta {{ color: #666; font-size: 0.9em; }}
        </style>
    </head>
    <body>
        <h1>PII / Sensitive Data Risk Scan Report</h1>
        <p class="meta">Generated: {timestamp}</p>

        <div class="banner">
            <h2>Risk Level: {risk['risk_level']}</h2>
            <p>{risk['reason']}</p>
        </div>

        <p><strong>Total rows scanned:</strong> {risk['total_rows']}</p>
        <p><strong>Rows containing PII:</strong> {risk['affected_rows']} ({risk['pct_affected']}%)</p>
        <p><strong>Total findings:</strong> {summary['total']}</p>

        <h2>Findings by PII Type</h2>
        <table><tr><th>Type</th><th>Count</th></tr>{type_rows}</table>

        <h2>Findings by Column (risk concentration)</h2>
        <table><tr><th>Column</th><th>Count</th></tr>{column_rows}</table>

        <h2>Full Findings</h2>
        <table>
            <tr><th>Row</th><th>Column</th><th>PII Type</th><th>Masked Value</th></tr>
            {finding_rows}
        </table>
    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"HTML report written to {output_path}")


if __name__ == "__main__":
    df = pd.read_csv("data/sample_customers.csv")
    findings = scan_dataframe(df)
    risk = assess_risk(findings, total_rows=len(df))

    summary = summarize(findings)
    print("Summary:", summary)
    print(f"Risk level: {risk['risk_level']}")
    print(f"Reason: {risk['reason']}")

    generate_csv_report(findings)
    generate_html_report(findings, risk)
