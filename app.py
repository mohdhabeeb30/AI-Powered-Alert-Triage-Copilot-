"""Streamlit dashboard for the AI-Powered Alert Triage Copilot."""

from __future__ import annotations

import json
from typing import Any

import requests
import streamlit as st

API_BASE_URL = "http://127.0.0.1:8000"
REQUEST_TIMEOUT_SECONDS = 8

DEFAULT_ALERT = {
    "alert_id": "ALERT-PLAYGROUND-001",
    "source": "Suricata IDS",
    "severity": "high",
    "alert_type": "SSH Brute Force",
    "source_ip": "185.220.101.42",
    "dest_ip": "10.0.1.15",
    "description": "847 failed SSH authentication attempts in 5 minutes from a suspicious external source.",
    "raw_payload": {
        "failed_attempts": 847,
        "window_minutes": 5,
        "abuseipdb_score": 98,
        "tor_exit_node": True,
        "usernames": ["root", "admin", "ubuntu"],
    },
}

st.set_page_config(
    page_title="Alert Triage Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
        .block-container { padding-top: 2rem; padding-bottom: 3rem; }
        [data-testid="stMetric"] {
            background: linear-gradient(135deg, #f7fbff 0%, #eef5f8 100%);
            border: 1px solid #d7e5e9;
            border-radius: 10px;
            padding: 1rem;
        }
        .status-banner {
            border-left: 5px solid #167d8d;
            background: #edf8f8;
            border-radius: 6px;
            padding: 0.8rem 1rem;
            color: #173f46;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def _offline_message() -> None:
    st.error("⚠️ Backend API Server Offline! Please run 'uvicorn main:app --reload' first.")
    st.stop()


def _request_json(
    method: str,
    path: str,
    *,
    params: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call the FastAPI gateway and return a validated JSON object."""
    try:
        response = requests.request(
            method,
            f"{API_BASE_URL}{path}",
            params=params,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        st.error(f"Backend request failed: {exc}")
        return {}
    except ValueError:
        st.error("Backend returned an invalid JSON response.")
        return {}

    if not isinstance(data, dict):
        st.error("Backend returned an unexpected response shape.")
        return {}
    return data


def _validate_backend() -> dict[str, Any]:
    """Confirm the API is reachable before rendering dashboard workflows."""
    try:
        response = requests.get(
            f"{API_BASE_URL}/api/v1/metrics",
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        _offline_message()

    if not isinstance(data, dict):
        _offline_message()
    return data


def _percentage(value: Any) -> str:
    """Format a ratio as a percentage with one decimal place."""
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "0.0%"


def _render_metrics(metrics: dict[str, Any]) -> None:
    st.subheader("Live Performance")
    st.caption("Metrics are calculated from historical triage decisions with analyst labels.")
    columns = st.columns(4)
    cards = (
        ("Precision", "precision", "Threat Detection"),
        ("Recall", "recall", "Threat Coverage"),
        ("F1-Score", "f1_score", "Balanced Accuracy"),
        ("Deflection Rate", "deflection_rate", "False Alarms Cut"),
    )
    for column, (label, key, delta) in zip(columns, cards):
        column.metric(label, _percentage(metrics.get(key, 0.0)), delta)

    total = metrics.get("total_alerts", 0)
    st.markdown(
        f'<div class="status-banner"><strong>{total}</strong> labeled alert decisions currently contribute to these KPIs.</div>',
        unsafe_allow_html=True,
    )


def _render_feedback_form() -> None:
    st.subheader("Analyst Override")
    st.caption("Correct a prior decision so future triage prompts can learn from the review.")
    with st.form("feedback_form", clear_on_submit=False):
        alert_id = st.text_input("Target Alert ID", placeholder="ALERT-BRUTE01")
        analyst_id = st.text_input("Analyst ID", value="soc-analyst")
        original = st.selectbox("Original Classification", options=("TP", "FP"))
        corrected = st.selectbox("Corrected Classification", options=("FP", "TP"))
        rationale = st.text_area(
            "Analyst Rationale",
            placeholder="Explain the evidence, approved change ticket, scanner profile, or threat indicators.",
            height=140,
        )
        submitted = st.form_submit_button("Submit Analyst Correction", type="primary")

    if not submitted:
        return
    if not alert_id.strip() or not analyst_id.strip() or not rationale.strip():
        st.warning("Alert ID, Analyst ID, and Analyst Rationale are required.")
        return

    feedback_payload = {
        "alert_id": alert_id.strip(),
        "original_classification": original,
        "corrected_classification": corrected,
        "analyst_id": analyst_id.strip(),
        "feedback_notes": rationale.strip(),
        "alert_type": "",
    }
    result = _request_json("POST", "/api/v1/feedback", payload=feedback_payload)
    if result:
        st.success(f"Analyst correction saved for {alert_id.strip()}.")
        st.rerun()


def _render_playground() -> None:
    st.subheader("Manual Ingestion Playground")
    st.caption("Paste a RawAlert JSON payload and send it through the triage engine.")
    live_mode = st.sidebar.toggle(
        "Use live Gemini analysis",
        value=False,
        help="When enabled, the backend attempts ADK first and falls back safely if quota or configuration fails.",
    )
    st.sidebar.caption(f"Analysis mode: {'LIVE' if live_mode else 'DETERMINISTIC MOCK'}")

    raw_json = st.text_area(
        "Raw security alert JSON",
        value=json.dumps(DEFAULT_ALERT, indent=2),
        height=360,
        key="raw_alert_json",
    )
    if not st.button("Run Triage Analysis", type="primary"):
        return

    try:
        alert_payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        st.error(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}")
        return

    if not isinstance(alert_payload, dict):
        st.error("The alert payload must be a JSON object.")
        return

    with st.spinner("Analyzing security alert..."):
        result = _request_json(
            "POST",
            "/api/v1/alerts/triage",
            params={"live": str(live_mode).lower()},
            payload=alert_payload,
        )

    if not result:
        return
    classification = result.get("classification", "UNKNOWN")
    is_true_positive = classification in {"TP", "TRUE_POSITIVE"}
    if is_true_positive:
        st.error("TRUE POSITIVE · THREAT", icon="🚨")
    elif classification == "FP":
        st.success("FALSE POSITIVE · NOISE", icon="✅")
    else:
        st.warning("UNRECOGNIZED CLASSIFICATION")

    left, right = st.columns((1, 2))
    with left:
        st.metric("Confidence", _percentage(result.get("confidence", 0.0)))
        st.write("**Recommended Action**")
        st.write(result.get("recommended_action", "Manual review required."))
    with right:
        st.write("**Reasoning**")
        st.write(result.get("reasoning", "No reasoning returned."))
        st.write("**MITRE ATT&CK Mapping**")
        st.write(", ".join(result.get("mitre_tactics", [])) or "Not applicable")

    if is_true_positive:
        technique_id = result.get("mitre_technique_id") or "Technique pending analyst validation"
        severity_justification = result.get(
            "severity_justification",
            "No severity justification was returned.",
        )
        remediation_steps = result.get("remediation_steps", [])
        if not isinstance(remediation_steps, list):
            remediation_steps = []

        st.error("Threat Intelligence Enrichment", icon="⚠️")
        st.markdown(f"**MITRE ATT&CK Technique ID**\n\n`{technique_id}`")
        st.info(
            f"**Severity Justification**\n\n{severity_justification}",
            icon="📌",
        )

        st.write("**Immediate Remediation Checklist**")
        alert_key = str(result.get("alert_id", "unknown-alert"))
        if remediation_steps:
            for index, step in enumerate(remediation_steps[:3], start=1):
                st.checkbox(
                    f"Step {index}: {step}",
                    key=f"remediation_{alert_key}_{index}",
                )
        else:
            st.warning("No remediation steps were returned for this threat.")

    st.json(result)


backend_metrics = _validate_backend()
st.title("🛡️ AI-Powered Alert Triage Copilot")
st.caption("SOC-L2 decision support with human feedback and deterministic resilience.")

analytics_tab, feedback_tab, playground_tab = st.tabs(
    ["📊 Analytics", "✍️ Analyst Feedback", "🧪 Triage Playground"]
)
with analytics_tab:
    _render_metrics(backend_metrics)
with feedback_tab:
    _render_feedback_form()
with playground_tab:
    _render_playground()
