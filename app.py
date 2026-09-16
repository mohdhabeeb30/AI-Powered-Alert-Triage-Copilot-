"""Streamlit dashboard for the AI-Powered Alert Triage Copilot."""

from __future__ import annotations

import json
from html import escape
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
    page_title="Nightwatch SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
        :root {
            --soc-black: #090E1A;
            --soc-panel: #0D1524;
            --soc-panel-raised: #111C2D;
            --soc-border: #1E293B;
            --soc-cyan: #22D3EE;
            --soc-emerald: #10B981;
            --soc-red: #EF4444;
            --soc-amber: #F59E0B;
            --soc-text: #D7E3F4;
            --soc-muted: #7890AA;
        }
        html, body, [class*="css"], button, input, textarea, select {
            font-family: "Courier New", Monaco, "Lucida Console", monospace !important;
        }
        .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
            background: var(--soc-black);
            color: var(--soc-text);
        }
        .stApp {
            background-image: linear-gradient(rgba(34, 211, 238, 0.025) 1px, transparent 1px),
                linear-gradient(90deg, rgba(34, 211, 238, 0.025) 1px, transparent 1px);
            background-size: 32px 32px;
        }
        .block-container { max-width: 1560px; padding: 1.2rem 2.4rem 4rem; }
        [data-testid="stSidebar"] {
            background: #080C14;
            border-right: 1px solid var(--soc-border);
        }
        [data-testid="stSidebar"] * {
            font-family: "Courier New", "Lucida Console", monospace;
        }
        .stMarkdown, .stCaption, [data-testid="stMetricLabel"],
        [data-testid="stMetricValue"], [data-testid="stMetricDelta"],
        textarea, input, button, code, pre, [data-testid="stJson"] {
            font-family: "Courier New", "Lucida Console", monospace !important;
        }
        .stMarkdown, [data-testid="stText"], label, p, li {
            color: var(--soc-text);
        }
        h1, h2, h3 { letter-spacing: 0.08em; color: #F8FAFC; text-transform: uppercase; }
        h1 { font-size: clamp(1.7rem, 3vw, 3rem); line-height: 1.1; text-shadow: 0 0 24px rgba(34, 211, 238, 0.22); }
        [data-testid="stTabs"] [role="tablist"] {
            gap: 0.4rem;
            border-bottom: 1px solid var(--soc-border);
        }
        [data-testid="stTabs"] button {
            color: var(--soc-muted);
            border: 1px solid transparent;
            border-bottom: 2px solid transparent;
            font-family: "Courier New", "Lucida Console", monospace;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        [data-testid="stTabs"] button[aria-selected="true"] {
            color: var(--soc-cyan);
            border-color: var(--soc-border);
            border-bottom-color: var(--soc-cyan);
            background: rgba(34, 211, 238, 0.08);
            box-shadow: 0 0 18px rgba(34, 211, 238, 0.14);
        }
        [data-testid="stForm"], [data-testid="stExpander"],
        [data-testid="stTextArea"], [data-testid="stTextInput"],
        [data-testid="stSelectbox"], [data-testid="stRadio"], [data-testid="stCheckbox"],
        [data-testid="stDataFrame"] {
            border: 1px solid var(--soc-border);
            background: rgba(15, 23, 42, 0.76);
            box-shadow: 0 0 18px rgba(0, 242, 254, 0.06);
        }
        [data-testid="stTextArea"] textarea, [data-testid="stTextInput"] input,
        [data-baseweb="select"] > div, [data-baseweb="textarea"] {
            color: var(--soc-text);
            background: #080C14;
            border-color: var(--soc-border);
            border-radius: 0;
        }
        [data-testid="stButton"] button, [data-testid="stFormSubmitButton"] button {
            border: 1px solid var(--soc-cyan);
            color: var(--soc-cyan);
            background: rgba(34, 211, 238, 0.07);
            font-family: "Courier New", "Lucida Console", monospace;
            box-shadow: 0 0 18px rgba(34, 211, 238, 0.14);
        }
        [data-testid="stButton"] button:hover, [data-testid="stFormSubmitButton"] button:hover {
            color: #FFFFFF;
            background: rgba(34, 211, 238, 0.18);
            box-shadow: 0 0 25px rgba(34, 211, 238, 0.3);
        }
        .soc-kpi-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.8rem; margin: 1rem 0 1.4rem; }
        .soc-kpi-card {
            min-height: 128px;
            padding: 1.1rem 1.2rem;
            background: linear-gradient(145deg, var(--soc-panel-raised), var(--soc-panel));
            border: 1px solid var(--soc-border);
            box-shadow: 0 0 18px rgba(34, 211, 238, 0.11);
            position: relative;
            overflow: hidden;
        }
        .soc-kpi-card::after { content: ""; position: absolute; width: 80px; height: 80px; right: -34px; bottom: -40px; border: 1px solid rgba(34, 211, 238, 0.2); transform: rotate(45deg); }
        .soc-kpi-label { color: var(--soc-muted); font-size: 0.72rem; letter-spacing: 0.1em; text-transform: uppercase; }
        .soc-kpi-value { margin: 0.55rem 0 0.35rem; color: var(--soc-cyan); font-size: 2rem; font-weight: 700; }
        .soc-kpi-value.high { color: var(--soc-emerald); text-shadow: 0 0 14px rgba(16, 185, 129, 0.5); }
        .soc-kpi-value.critical { color: var(--soc-red); text-shadow: 0 0 14px rgba(239, 68, 68, 0.5); }
        .soc-kpi-delta { color: var(--soc-muted); font-size: 0.72rem; }
        .status-banner, .soc-panel {
            border: 1px solid var(--soc-border);
            background: rgba(15, 23, 42, 0.78);
            box-shadow: 0 0 18px rgba(0, 242, 254, 0.07);
            padding: 0.9rem 1rem;
        }
        .console-header { display: flex; justify-content: space-between; align-items: flex-end; gap: 1rem; border-bottom: 1px solid var(--soc-border); padding-bottom: 1.2rem; margin-bottom: 1rem; }
        .eyebrow, .soc-label { color: var(--soc-cyan); font-size: 0.68rem; font-weight: 700; letter-spacing: 0.16em; text-transform: uppercase; }
        .header-status { color: var(--soc-emerald); font-size: 0.68rem; letter-spacing: 0.1em; white-space: nowrap; }
        .header-status::before { content: ""; display: inline-block; width: 7px; height: 7px; margin-right: 0.5rem; background: var(--soc-emerald); box-shadow: 0 0 9px var(--soc-emerald); }
        .console-strap { color: var(--soc-muted); font-size: 0.73rem; letter-spacing: 0.08em; }
        .section-rule { display: flex; align-items: center; gap: 0.8rem; margin: 1.25rem 0 0.7rem; color: var(--soc-muted); font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase; }
        .section-rule::after { content: ""; height: 1px; flex: 1; background: var(--soc-border); }
        .sidebar-readout { border: 1px solid var(--soc-border); padding: 0.8rem; margin: 0.8rem 0; background: rgba(13, 21, 36, 0.9); box-shadow: 0 0 18px rgba(34, 211, 238, 0.11); }
        .sidebar-value { color: var(--soc-text); font-size: 0.78rem; margin-top: 0.3rem; }
        .remediation-card [data-testid="stCheckbox"] { border: 0; box-shadow: none; background: transparent; padding: 0; }
        .status-banner { border-left: 4px solid var(--soc-emerald); color: var(--soc-text); }
        .tp-alert {
            border: 1px solid rgba(239, 68, 68, 0.62);
            border-left: 5px solid var(--soc-red);
            background: rgba(69, 10, 10, 0.36);
            box-shadow: 0 0 24px rgba(239, 68, 68, 0.18);
            padding: 1rem 1.1rem;
            animation: threat-pulse 1.8s ease-in-out infinite alternate;
        }
        .tp-ribbon { color: #FFFFFF; font-weight: 700; letter-spacing: 0.12em; }
        .tp-technique { color: var(--soc-red); font-size: 1.3rem; font-weight: 700; }
        .tp-severity { color: var(--soc-text); line-height: 1.6; }
        .remediation-card {
            border: 1px solid var(--soc-border);
            background: rgba(17, 28, 49, 0.78);
            padding: 0.75rem;
            min-height: 92px;
        }
        @keyframes threat-pulse { from { box-shadow: 0 0 10px rgba(239, 68, 68, 0.12); } to { box-shadow: 0 0 28px rgba(239, 68, 68, 0.32); } }
        @media (max-width: 900px) { .soc-kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .block-container { padding: 1rem 1rem 3rem; } .console-header { align-items: flex-start; flex-direction: column; } }
        @media (max-width: 560px) { .soc-kpi-grid { grid-template-columns: 1fr; } }
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
    st.markdown('<div class="section-rule">01 // telemetry performance matrix</div>', unsafe_allow_html=True)
    st.caption("Historical labeled decisions · FastAPI gateway :8000 · SQLite telemetry")
    cards = (
        ("Precision", "precision", "Threat Detection"),
        ("Recall", "recall", "Threat Coverage"),
        ("F1-Score", "f1_score", "Balanced Accuracy"),
        ("Deflection Rate", "deflection_rate", "False Alarms Cut"),
    )
    card_markup = []
    for label, key, delta in cards:
        try:
            ratio = float(metrics.get(key, 0.0))
        except (TypeError, ValueError):
            ratio = 0.0
        tone = "high" if ratio >= 0.8 and key in {"precision", "deflection_rate"} else ""
        if ratio < 0.5:
            tone = "critical"
        card_markup.append(
            f'<div class="soc-kpi-card"><div class="soc-kpi-label">{escape(label)}</div>'
            f'<div class="soc-kpi-value {tone}">{_percentage(ratio)}</div>'
            f'<div class="soc-kpi-delta">↳ {escape(delta)}</div></div>'
        )
    st.markdown(f'<div class="soc-kpi-grid">{"".join(card_markup)}</div>', unsafe_allow_html=True)

    total = metrics.get("total_alerts", 0)
    st.markdown(
        f'<div class="status-banner"><strong>{total}</strong> labeled alert decisions currently contribute to these KPIs.</div>',
        unsafe_allow_html=True,
    )


def _render_feedback_form() -> None:
    st.markdown('<div class="section-rule">02 // analyst override channel</div>', unsafe_allow_html=True)
    st.caption("Feed a reviewed decision back into the few-shot matrix for future triage.")
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
    st.markdown('<div class="section-rule">03 // incident ingestion workbench</div>', unsafe_allow_html=True)
    st.caption("Submit a RawAlert payload to the SOC-L2 decision pipeline.")
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
        st.markdown(
            '<div class="tp-alert"><div class="tp-ribbon">🚨 CRITICAL MITRE ATT&CK THREAT ENRICHMENT IDENTIFIED</div>'
            '<div class="soc-kpi-delta">TRUE POSITIVE · ACTIVE THREAT SIGNAL · L2 ESCALATION REQUIRED</div></div>',
            unsafe_allow_html=True,
        )
    elif classification == "FP":
        st.markdown(
            '<div class="soc-panel" style="border-left: 5px solid #10B981;">'
            '<strong style="color:#10B981;">✓ FALSE POSITIVE · NOISE</strong>'
            '<div class="soc-kpi-delta">Benign or approved activity profile</div></div>',
            unsafe_allow_html=True,
        )
    else:
        st.warning("UNRECOGNIZED CLASSIFICATION")

    left, right = st.columns((1, 2))
    with left:
        st.markdown(
            f'<div class="soc-kpi-card"><div class="soc-kpi-label">Decision Confidence</div>'
            f'<div class="soc-kpi-value">{_percentage(result.get("confidence", 0.0))}</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="soc-panel"><div class="soc-kpi-label">Recommended Action</div>', unsafe_allow_html=True)
        st.write(result.get("recommended_action", "Manual review required."))
        st.markdown("</div>", unsafe_allow_html=True)
    with right:
        st.markdown('<div class="soc-panel"><div class="soc-kpi-label">Analyst Reasoning</div>', unsafe_allow_html=True)
        st.write(result.get("reasoning", "No reasoning returned."))
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown('<div class="soc-panel"><div class="soc-kpi-label">MITRE ATT&CK Tactics</div>', unsafe_allow_html=True)
        st.write(", ".join(result.get("mitre_tactics", [])) or "Not applicable")
        st.markdown("</div>", unsafe_allow_html=True)

    if is_true_positive:
        technique_id = result.get("mitre_technique_id") or "Technique pending analyst validation"
        severity_justification = result.get(
            "severity_justification",
            "No severity justification was returned.",
        )
        remediation_steps = result.get("remediation_steps", [])
        if not isinstance(remediation_steps, list):
            remediation_steps = []

        st.markdown(
            f'<div class="tp-alert"><div class="soc-kpi-label">MITRE ATT&CK TECHNIQUE ID</div>'
            f'<div class="tp-technique">{escape(str(technique_id))}</div>'
            f'<div class="soc-kpi-label" style="margin-top:1rem;">SEVERITY JUSTIFICATION</div>'
            f'<div class="tp-severity">{escape(str(severity_justification))}</div></div>',
            unsafe_allow_html=True,
        )

        st.markdown('<div class="section-rule">remediation protocol // operator acknowledgement</div>', unsafe_allow_html=True)
        alert_key = str(result.get("alert_id", "unknown-alert"))
        if remediation_steps:
            checklist_columns = st.columns(min(len(remediation_steps[:3]), 3))
            for index, (column, step) in enumerate(
                zip(checklist_columns, remediation_steps[:3]),
                start=1,
            ):
                with column:
                    st.markdown('<div class="remediation-card">', unsafe_allow_html=True)
                    st.checkbox(
                        f"STEP {index}",
                        key=f"remediation_{alert_key}_{index}",
                    )
                    st.caption(str(step))
                    st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.warning("No remediation steps were returned for this threat.")

    st.json(result)


backend_metrics = _validate_backend()
st.markdown(
    '<div class="console-header"><div><div class="eyebrow">NIGHTWATCH // SOC-L2 OPERATIONS CONSOLE</div>'
    '<div class="console-strap">AI-POWERED ALERT TRIAGE COPILOT / COMMAND CHANNEL 8000</div></div>'
    '<div class="header-status">FASTAPI LINK ESTABLISHED</div></div>',
    unsafe_allow_html=True,
)
st.title("AI-Powered Alert Triage Copilot")
st.caption("LIVE TELEMETRY · HUMAN-IN-THE-LOOP · DETERMINISTIC RESILIENCE")

st.sidebar.markdown('<div class="eyebrow">NIGHTWATCH // CONTROL PLANE</div>', unsafe_allow_html=True)
st.sidebar.markdown(
    '<div class="sidebar-readout"><div class="soc-label">SYSTEM STATE</div><div class="sidebar-value">● OPERATIONAL</div></div>'
    '<div class="sidebar-readout"><div class="soc-label">TELEMETRY SOURCE</div><div class="sidebar-value">SQLITE / FASTAPI</div></div>'
    '<div class="sidebar-readout"><div class="soc-label">DECISION TIER</div><div class="sidebar-value">SOC-L2 TRIAGE</div></div>',
    unsafe_allow_html=True,
)

analytics_tab, feedback_tab, playground_tab = st.tabs(
    ["📊 Analytics", "✍️ Analyst Feedback", "🧪 Triage Playground"]
)
with analytics_tab:
    _render_metrics(backend_metrics)
with feedback_tab:
    _render_feedback_form()
with playground_tab:
    _render_playground()
