import pandas as pd
from detectors import find_emails, find_phones, find_credit_cards


def mask_value(value: str) -> str:
    """
    Masks a sensitive value for safe display in reports.
    Never show full PII, even fake data — good practice to demonstrate.
    e.g. 'john.doe@example.com' -> 'jo***********om'
    """
    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def scan_dataframe(df: pd.DataFrame) -> list:
    """
    Scans every cell in the DataFrame for PII.
    Returns a list of findings, each a dict with:
    row index, column name, PII type, and masked value.
    """
    findings = []

    for col in df.columns:
        for row_idx, cell_value in df[col].items():
            cell_str = str(cell_value)

            emails = find_emails(cell_str)
            phones = find_phones(cell_str)
            cards = find_credit_cards(cell_str)

            for match in emails:
                findings.append({
                    "row": row_idx,
                    "column": col,
                    "pii_type": "email",
                    "value_masked": mask_value(match),
                })
            for match in phones:
                findings.append({
                    "row": row_idx,
                    "column": col,
                    "pii_type": "phone",
                    "value_masked": mask_value(match),
                })
            for match in cards:
                findings.append({
                    "row": row_idx,
                    "column": col,
                    "pii_type": "credit_card",
                    "value_masked": mask_value(match),
                })

    return findings

def assess_risk(findings: list, total_rows: int) -> dict:
    """
    Takes the list of findings from scan_dataframe() and produces
    a risk level + human-readable justification.
    """
    card_findings = [f for f in findings if f["pii_type"] == "credit_card"]
    email_findings = [f for f in findings if f["pii_type"] == "email"]
    phone_findings = [f for f in findings if f["pii_type"] == "phone"]

    # unique rows that have at least one PII finding of any type
    affected_rows = set(f["row"] for f in findings)
    pct_affected = (len(affected_rows) / total_rows) * 100 if total_rows else 0

    num_cards = len(card_findings)

    # --- risk rules, most severe checked first ---
    if num_cards > 0:
        level = "High"
        reason = (
            f"{num_cards} credit card number(s) detected. "
            f"Card data exposure carries PCI-DSS compliance risk."
        )
    elif pct_affected > 50:
        level = "Medium-High"
        reason = (
            f"{pct_affected:.1f}% of rows contain PII "
            f"(emails: {len(email_findings)}, phones: {len(phone_findings)}). "
            f"Widespread exposure across the dataset."
        )
    elif pct_affected > 0:
        level = "Medium"
        reason = (
            f"{pct_affected:.1f}% of rows contain PII, "
            f"limited to lower-sensitivity types (email/phone)."
        )
    else:
        level = "Low"
        reason = "No PII detected in this dataset."

    return {
        "risk_level": level,
        "reason": reason,
        "total_findings": len(findings),
        "affected_rows": len(affected_rows),
        "total_rows": total_rows,
        "pct_affected": round(pct_affected, 1),
        "credit_card_count": num_cards,
        "email_count": len(email_findings),
        "phone_count": len(phone_findings),
    }

if __name__ == "__main__":
    df = pd.read_csv("data/sample_customers.csv")
    results = scan_dataframe(df)
    risk = assess_risk(results, total_rows=len(df))

    print(f"Scanned {len(df)} rows across {len(df.columns)} columns.")
    print(f"Total PII findings: {len(results)}")
    print(f"Risk level: {risk['risk_level']}")
    print(f"Reason: {risk['reason']}")