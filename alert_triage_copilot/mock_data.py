"""
Mock Security Alert Data & Ground Truth Labels.

Provides 5 diverse security alerts spanning common SOC scenarios:
brute-force attacks, phishing, scanner noise, DNS exfiltration,
and routine update traffic. Each alert has a ground-truth label
for evaluation.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .schemas import Classification, RawAlert, Severity


# ──────────────────────────────────────────────────────────────────────
#  Ground Truth Mapping  (alert_id → actual classification)
# ──────────────────────────────────────────────────────────────────────

GROUND_TRUTH: dict[str, Classification] = {
    "ALERT-BRUTE01": Classification.TRUE_POSITIVE,
    "ALERT-PHISH02": Classification.TRUE_POSITIVE,
    "ALERT-SCAN03":  Classification.FALSE_POSITIVE,
    "ALERT-DNSEX04": Classification.TRUE_POSITIVE,
    "ALERT-WDEF05":  Classification.FALSE_POSITIVE,
}


# ──────────────────────────────────────────────────────────────────────
#  Mock Alerts
# ──────────────────────────────────────────────────────────────────────

MOCK_ALERTS: list[RawAlert] = [

    # ─── 1. SSH Brute Force (TRUE POSITIVE) ──────────────────────────
    RawAlert(
        alert_id="ALERT-BRUTE01",
        timestamp=datetime(2026, 9, 5, 10, 23, 45, tzinfo=timezone.utc),
        source="Suricata IDS",
        severity=Severity.CRITICAL,
        alert_type="SSH Brute Force",
        source_ip="185.220.101.42",
        dest_ip="10.0.1.15",
        description=(
            "847 failed SSH login attempts detected from external IP 185.220.101.42 "
            "targeting server 10.0.1.15 within a 5-minute window. Multiple usernames "
            "attempted including 'root', 'admin', 'ubuntu'. Source IP is listed on "
            "AbuseIPDB with 98% confidence score."
        ),
        raw_payload={
            "signature_id": "2001219",
            "signature": "ET SCAN Potential SSH Scan",
            "failed_attempts": 847,
            "unique_usernames": ["root", "admin", "ubuntu", "deploy", "git"],
            "time_window_seconds": 300,
            "abuseipdb_score": 98,
            "geo_location": "Frankfurt, DE",
            "tor_exit_node": True,
        },
    ),

    # ─── 2. Phishing Email (TRUE POSITIVE) ──────────────────────────
    RawAlert(
        alert_id="ALERT-PHISH02",
        timestamp=datetime(2026, 9, 5, 11, 7, 12, tzinfo=timezone.utc),
        source="Proofpoint Email Gateway",
        severity=Severity.HIGH,
        alert_type="Phishing Email",
        source_ip="203.0.113.88",
        dest_ip="10.0.2.50",
        description=(
            "Inbound email from spoofed address 'ceo@company-corp.co' (actual domain: "
            "company-corp.co, NOT company-corp.com) to CFO mailbox. Contains password-"
            "protected ZIP attachment 'Q3_Financial_Review.zip' with embedded macro-"
            "enabled Excel file. Email header analysis shows SPF fail and DKIM mismatch."
        ),
        raw_payload={
            "from_header": "CEO John Smith <ceo@company-corp.co>",
            "envelope_from": "bounce-x928@mail-relay.xyz",
            "to": "cfo@company-corp.com",
            "subject": "URGENT: Q3 Financial Review — Action Required",
            "attachment": "Q3_Financial_Review.zip",
            "spf_result": "fail",
            "dkim_result": "fail",
            "dmarc_result": "reject",
            "x_mailer": "PHPMailer 6.1.4",
            "attachment_hash_sha256": "a1b2c3d4e5f678901234567890abcdef12345678",
            "virustotal_detections": 23,
        },
    ),

    # ─── 3. Port Scan — Nessus Scanner (FALSE POSITIVE) ─────────────
    RawAlert(
        alert_id="ALERT-SCAN03",
        timestamp=datetime(2026, 9, 5, 14, 0, 5, tzinfo=timezone.utc),
        source="Palo Alto NGFW",
        severity=Severity.MEDIUM,
        alert_type="Port Scan",
        source_ip="10.0.50.10",
        dest_ip="10.0.1.0/24",
        description=(
            "Sequential port scanning activity detected from 10.0.50.10 targeting the "
            "entire 10.0.1.0/24 subnet. 65,535 ports scanned per host. Activity matches "
            "Nessus vulnerability scanner fingerprint."
        ),
        raw_payload={
            "scanner_fingerprint": "Nessus/10.7.0",
            "scan_type": "full_tcp_syn",
            "ports_scanned": 65535,
            "hosts_scanned": 254,
            "scheduled_window": "2026-09-05T14:00:00Z/2026-09-05T16:00:00Z",
            "approved_change_ticket": "CHG-2026-04521",
            "scanner_registered": True,
            "internal_asset": True,
        },
    ),

    # ─── 4. DNS Exfiltration (TRUE POSITIVE) ────────────────────────
    RawAlert(
        alert_id="ALERT-DNSEX04",
        timestamp=datetime(2026, 9, 5, 15, 42, 33, tzinfo=timezone.utc),
        source="Cisco Umbrella",
        severity=Severity.HIGH,
        alert_type="DNS Exfiltration",
        source_ip="10.0.3.77",
        dest_ip="8.8.8.8",
        description=(
            "Workstation 10.0.3.77 generated 2,340 DNS TXT queries to subdomains of "
            "'data-x7k9.top' in 10 minutes. Subdomain labels contain high-entropy "
            "base64-encoded strings (avg 48 chars). Domain registered 3 days ago via "
            "anonymous registrar. Pattern consistent with DNS tunneling / data exfiltration."
        ),
        raw_payload={
            "query_count": 2340,
            "time_window_minutes": 10,
            "domain": "data-x7k9.top",
            "subdomain_entropy_avg": 4.82,
            "subdomain_length_avg": 48,
            "domain_age_days": 3,
            "registrar": "NameSilo (privacy-protected)",
            "query_type": "TXT",
            "dns_server": "8.8.8.8",
            "known_c2_domain": False,
            "ml_anomaly_score": 0.96,
        },
    ),

    # ─── 5. Windows Defender Update (FALSE POSITIVE) ────────────────
    RawAlert(
        alert_id="ALERT-WDEF05",
        timestamp=datetime(2026, 9, 5, 16, 15, 0, tzinfo=timezone.utc),
        source="Microsoft Defender for Endpoint",
        severity=Severity.LOW,
        alert_type="Suspicious Outbound Connection",
        source_ip="10.0.4.22",
        dest_ip="13.107.4.50",
        description=(
            "Endpoint 10.0.4.22 initiated HTTPS connection to 13.107.4.50 "
            "(Microsoft Update CDN) for Windows Defender signature update. "
            "Triggered generic 'outbound connection to external IP' rule. "
            "Connection matches known Microsoft update infrastructure."
        ),
        raw_payload={
            "process": "MsMpEng.exe",
            "process_path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2026.9\\MsMpEng.exe",
            "dest_hostname": "definitionupdates.microsoft.com",
            "dest_ip_owner": "Microsoft Corporation",
            "tls_sni": "definitionupdates.microsoft.com",
            "certificate_issuer": "Microsoft Azure RSA TLS Issuing CA 08",
            "bytes_sent": 1024,
            "bytes_received": 2_457_600,
            "connection_duration_sec": 4.2,
            "microsoft_ip_range": True,
        },
    ),
]


def get_mock_alerts() -> list[RawAlert]:
    """Return a fresh copy of the mock alert dataset."""
    return list(MOCK_ALERTS)


def get_ground_truth() -> dict[str, Classification]:
    """Return the ground truth classification map."""
    return dict(GROUND_TRUTH)
