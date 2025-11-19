import csv
from pathlib import Path
from typing import List

from ..models.finding import Finding, DependencyFinding, SecretFinding


def format_security_check_results(findings: List[Finding], output_path: Path) -> None:
    if not findings:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "check_id",
        "title",
        "severity",
        "category",
        "resource",
        "evidence",
        "description",
        "risk",
        "remediation",
        "reference_url",
        "notes",
        "timestamp",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow(finding.to_dict())


def format_dependency_findings(
    findings: List[DependencyFinding], output_path: Path
) -> None:
    if not findings:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "repository",
        "package",
        "version",
        "ecosystem",
        "file_path",
        "severity",
        "advisory_id",
        "title",
        "cvss_score",
        "url",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow(finding.to_dict())


def format_secret_findings(findings: List[SecretFinding], output_path: Path) -> None:
    if not findings:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "repository",
        "file_path",
        "secret_type",
        "line_number",
        "secret_hash",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow(finding.to_dict())
