# PII Risk Scanner

A Python tool that scans tabular datasets for personally identifiable information (PII), 
classifies overall risk severity, and generates an audit-style HTML/CSV report - 
built as a lightweight example of sensitive data discovery, similar in concept to 
enterprise DLP (Data Loss Prevention) tooling.

## Why I built this

I'm currently completing a Master's in Cybersecurity (with a background in a Bachelor's 
of Computer Science and software development internships). This project explores how 
sensitive data discovery and risk classification work in practice - the kind of problem 
relevant to any organisation handling client data at scale.

## What it does

1. **Generates synthetic test data** - a fake customer dataset (names, emails, AU phone 
   numbers, credit card numbers) using the `Faker` library, so no real personal data is 
   ever used.
2. **Scans every column of the dataset** using regex pattern matching to detect:
   - Email addresses
   - Australian phone numbers
   - Credit card numbers (validated using the **Luhn algorithm** to reduce false positives - 
     the same checksum method used in real payment card validation)
3. **Assesses risk** based on the type and volume of PII found (e.g. any credit card 
   detection automatically triggers a "High" risk rating due to PCI-DSS implications).
4. **Generates a report** - both a machine-readable CSV and a styled HTML report with a 
   colour-coded risk banner, breakdown by PII type/column, and a masked findings table 
   (no PII is ever shown unmasked, even though the data is synthetic - a deliberate 
   design choice reflecting good data-handling practice).

## Tech stack

- Python 3.11
- `pandas` - data handling
- `Faker` - synthetic test data generation
- `re` (regex) - pattern-based PII detection
- Custom Luhn algorithm implementation - credit card validation

## Project structure

```
pii-risk-scanner/
├── generate_sample_data.py   # Creates synthetic test dataset
├── detectors.py              # Regex + Luhn detection logic
├── scanner.py                # Scans dataset, aggregates findings, assesses risk
├── report.py                 # Generates CSV + HTML reports
├── data/                      # Generated sample dataset
└── reports/                   # Generated output reports
```
## How to run it

```bash
pip install pandas faker
python generate_sample_data.py
python report.py
```

Open `reports/pii_report.html` in a browser to view the report.

## Known limitations

- Regex-based name detection isn't implemented (unstructured, high false-positive risk) - 
  a production tool would use NLP/NER models for this.
- The phone detector can occasionally flag digit substrings within other numeric fields 
  (e.g. credit card numbers) as false-positive phone matches, since every column is 
  checked against every detector. This is a deliberate trade-off - it means the tool 
  also catches PII sitting in the wrong column - but it's a known source of noise.
- Built as a 2-day proof-of-concept, not a production-grade DLP solution.
