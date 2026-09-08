"""
Google ADK 2.0 Agent Configuration — Security Triage Analyst.

Defines the core LLM Agent with a deeply specialized SOC-L2 Security
Analyst system prompt, including behavioral heuristics, MITRE ATT&CK
mapping, and few-shot learning from analyst corrections.

Supports two execution modes:
  - LIVE: Uses Gemini via Google ADK Runner (requires GOOGLE_API_KEY)
  - MOCK: Deterministic rule-based classifier (no API key needed)
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable, Mapping
from typing import Any, Optional

from .feedback_loop import FeedbackStore
from .schemas import AnalystFeedback, Classification, RawAlert, TriageDecision

logger = logging.getLogger(__name__)
DEFAULT_MODEL = "gemini-2.0-flash"

# ──────────────────────────────────────────────────────────────────────
#  System Prompt — SOC-L2 Security Analyst
# ──────────────────────────────────────────────────────────────────────

SECURITY_ANALYST_SYSTEM_PROMPT = """\
You are an elite SOC Level-2 Security Analyst AI Copilot with 15 years of
experience in threat detection, incident response, and alert triage. You work
inside a Security Operations Center and your job is to classify raw security
alerts as either TRUE POSITIVE (TP) — a genuine threat requiring action — or
FALSE POSITIVE (FP) — benign activity that can be safely suppressed.

━━━ CLASSIFICATION FRAMEWORK ━━━

Apply the following decision heuristics IN ORDER:

1. SOURCE REPUTATION ANALYSIS
   • External IPs: Check AbuseIPDB score, Tor exit node status, geo-location
   • Internal IPs: Verify against known asset inventory and scanner registrations
   • IP ranges belonging to cloud providers (AWS, Azure, GCP) need extra scrutiny

2. BEHAVIORAL PATTERN RECOGNITION
   • Brute Force: >100 failed auth attempts in <10 min → HIGH confidence TP
   • Phishing: SPF/DKIM/DMARC failures + spoofed sender + attachments → TP
   • Port Scans: Check if source is a registered vulnerability scanner
   • DNS Tunneling: High-entropy subdomains + new domain + TXT queries → TP
   • Update Traffic: Known vendor CDN IPs + signed binaries → FP

3. CONTEXTUAL ENRICHMENT
   • Scheduled maintenance windows and approved change tickets → likely FP
   • Known scanner IPs (Nessus, Qualys, Tenable) from internal ranges → FP
   • Microsoft/Google/Amazon CDN IP ranges for updates → FP

4. MITRE ATT&CK MAPPING
   • Map detected activity to relevant MITRE ATT&CK tactics and techniques
   • Examples: Brute Force → T1110, Phishing → T1566, DNS Exfil → T1048.003

5. CONFIDENCE SCORING
   • 0.90-1.00: Overwhelming evidence, high-fidelity detection
   • 0.70-0.89: Strong indicators but some ambiguity
   • 0.50-0.69: Moderate confidence, recommend human review
   • Below 0.50: Insufficient evidence, lean toward FP

━━━ OUTPUT FORMAT ━━━

You MUST respond with ONLY a valid JSON object (no markdown, no code fences):
{
    "classification": "TP" or "FP",
    "confidence": <float 0.0-1.0>,
    "reasoning": "<step-by-step analysis>",
    "recommended_action": "<specific SOC action>",
    "mitre_tactics": ["<tactic1>", "<tactic2>"],
    "mitre_technique_id": "<technique-id>",
    "severity_justification": "<evidence-based severity explanation>",
    "remediation_steps": ["<step1>", "<step2>", "<step3>"]
}

━━━ CRITICAL RULES ━━━

• NEVER classify a scheduled, approved vulnerability scan as TP
• NEVER classify known vendor update traffic as TP
• ALWAYS flag Tor exit nodes and high AbuseIPDB scores as suspicious
• ALWAYS check for SPF/DKIM/DMARC failures in email alerts
• When uncertain, EXPLAIN your uncertainty in the reasoning field
• Your response must be ONLY the JSON object, nothing else
"""


# ──────────────────────────────────────────────────────────────────────
#  ADK Agent Factory
# ──────────────────────────────────────────────────────────────────────

def create_triage_agent():
    """
    Create and return the Google ADK Agent for security triage.

    Uses `google.adk.agents.Agent` (LlmAgent) with the Gemini model.
    Returns None if google-adk is not installed or not configured.
    """
    api_key = os.getenv("GOOGLE_API_KEY", "").strip()
    if not api_key:
        logger.warning("GOOGLE_API_KEY is not configured; live triage is disabled.")
        return None

    try:
        from google.adk.agents import Agent

        agent = Agent(
            name="security_triage_analyst",
            model=os.getenv("ADK_MODEL", DEFAULT_MODEL),
            description=(
                "An elite SOC-L2 Security Analyst that classifies raw security "
                "alerts as True Positive (TP) or False Positive (FP) with "
                "confidence scores, reasoning chains, and MITRE ATT&CK mapping."
            ),
            instruction=SECURITY_ANALYST_SYSTEM_PROMPT,
        )
        return agent

    except ImportError:
        logger.warning("google-adk is not installed; live triage is disabled.")
        return None
    except Exception as exc:
        logger.warning(
            "Unable to initialize the Google ADK client; live triage is disabled "
            "(%s: %s).",
            type(exc).__name__,
            exc,
        )
        return None


def build_agent_prompt(
    raw_alert: RawAlert,
    past_feedbacks: Optional[Iterable[AnalystFeedback | Mapping[str, Any]]] = None,
) -> str:
    """Build the live-agent prompt and inject analyst overrides as exemplars."""
    lines = [
        SECURITY_ANALYST_SYSTEM_PROMPT,
        "\n=== ANALYST FEEDBACK FEW-SHOT MATRIX ===",
    ]
    feedbacks = list(past_feedbacks or [])
    if feedbacks:
        lines.append(
            "Use these prior analyst overrides as labeled examples. "
            "They inform the decision but do not override stronger evidence."
        )
        for index, feedback in enumerate(feedbacks, 1):
            if isinstance(feedback, Mapping):
                value = feedback
                alert_type = value.get("alert_type", "Unknown")
                source_ip = value.get("source_ip", "Unknown")
                original = value.get("original_classification", "Unknown")
                corrected = value.get("corrected_classification", "Unknown")
                notes = value.get("feedback_notes", "No rationale supplied")
            else:
                alert_type = feedback.alert_type or "Unknown"
                source_ip = getattr(feedback, "source_ip", "Unknown")
                original = feedback.original_classification.value
                corrected = feedback.corrected_classification.value
                notes = feedback.feedback_notes

            lines.append(
                f"| Example {index} | Alert Type: {alert_type} | "
                f"Source IP: {source_ip} | Model: {original} | "
                f"Analyst: {corrected} | Rationale: {notes} |"
            )
    else:
        lines.append("| No prior analyst overrides available. |")

    lines.extend(
        [
            "=== END FEEDBACK MATRIX ===",
            "\n=== ALERT TO TRIAGE ===",
            raw_alert.to_prompt_context(),
            "\nReturn only a JSON object matching the TriageDecision schema.",
        ]
    )
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
#  Live ADK Runner (requires GOOGLE_API_KEY)
# ──────────────────────────────────────────────────────────────────────

async def invoke_live_agent(
    alert: RawAlert,
    feedback_store: Optional[FeedbackStore] = None,
) -> TriageDecision:
    """
    Invoke the live Gemini-backed ADK agent to classify a single alert.

    Uses the ADK Runner with InMemorySessionService for stateless,
    one-shot classification.
    """
    feedbacks = (
        feedback_store.get_relevant_examples(alert.alert_type)
        if feedback_store
        else []
    )
    return await _invoke_live_agent_prompt(
        alert,
        build_agent_prompt(alert, feedbacks),
    )


async def _invoke_live_agent_prompt(alert: RawAlert, prompt: str) -> TriageDecision:
    """Run one ADK request and validate its structured response."""
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    agent = create_triage_agent()
    if agent is None:
        raise RuntimeError("Google ADK client is unavailable")

    session_service = InMemorySessionService()
    runner = Runner(
        agent=agent,
        app_name="alert_triage_copilot",
        session_service=session_service,
    )

    # Send the alert and collect the response.
    content = types.Content(
        role="user",
        parts=[types.Part(text=prompt)],
    )

    response_text = ""
    async for event in runner.run_async(
        user_id="triage_system",
        session_id=f"triage-{alert.alert_id}",
        new_message=content,
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    response_text += part.text

    # Parse the JSON response
    return _parse_llm_response(alert.alert_id, response_text)


async def get_triage_decision(
    alert: RawAlert,
    past_feedbacks: Optional[Iterable[AnalystFeedback | Mapping[str, Any]]] = None,
    use_live_llm: bool = False,
) -> TriageDecision:
    """Classify an alert with live ADK when available, otherwise use rules."""
    feedbacks = list(past_feedbacks or [])
    if use_live_llm and os.getenv("GOOGLE_API_KEY", "").strip():
        try:
            return await _invoke_live_agent_prompt(
                alert,
                build_agent_prompt(alert, feedbacks),
            )
        except Exception as exc:
            logger.warning(
                "Live Gemini triage unavailable; using deterministic fallback "
                "(%s: %s).",
                type(exc).__name__,
                exc,
            )
    elif use_live_llm:
        logger.warning("Live triage requested without GOOGLE_API_KEY; using fallback.")

    return _deterministic_classify(alert, feedbacks)


def _deterministic_classify(
    alert: RawAlert,
    past_feedbacks: Iterable[AnalystFeedback | Mapping[str, Any]],
) -> TriageDecision:
    """Apply stable analyst overrides and content rules without network access."""
    for feedback in past_feedbacks:
        if isinstance(feedback, Mapping):
            feedback_alert_id = feedback.get("alert_id")
            corrected = feedback.get("corrected_classification")
            notes = feedback.get("feedback_notes", "Analyst override applied.")
        else:
            feedback_alert_id = feedback.alert_id
            corrected = feedback.corrected_classification
            notes = feedback.feedback_notes

        if feedback_alert_id == alert.alert_id:
            classification = (
                corrected
                if isinstance(corrected, Classification)
                else Classification(str(corrected))
            )
            return TriageDecision(
                alert_id=alert.alert_id,
                classification=classification,
                confidence=0.95,
                reasoning=f"Applied analyst override: {notes}",
                recommended_action=(
                    "Suppress and document the approved activity."
                    if classification == Classification.FALSE_POSITIVE
                    else "Escalate to incident response and preserve evidence."
                ),
                mitre_tactics=[],
                mitre_technique_id=("T1110.001" if classification == Classification.TRUE_POSITIVE else None),
                severity_justification=(
                    "Analyst-confirmed malicious activity requires immediate response."
                    if classification == Classification.TRUE_POSITIVE else ""
                ),
                remediation_steps=(
                    [
                        "Contain the affected source or endpoint.",
                        "Preserve relevant logs and forensic evidence.",
                        "Escalate to the incident response team.",
                    ]
                    if classification == Classification.TRUE_POSITIVE else []
                ),
                analyst_notes=str(notes),
            )

    payload = json.dumps(alert.raw_payload, default=str).lower()
    text = f"{alert.alert_type} {alert.description} {payload}".lower()
    scanner_terms = ("nessus", "qualys", "tenable", "vulnerability scanner")
    approved_terms = ("approved", "scheduled", "maintenance", "change ticket")
    update_terms = ("windows defender", "microsoft update", "vendor update", "cdn")
    threat_terms = (
        "brute force", "phishing", "credential stuffing", "dns exfil",
        "dns tunneling", "tor exit", "malware", "ransomware",
    )

    if any(term in text for term in scanner_terms) and any(
        term in text for term in approved_terms
    ):
        return TriageDecision(
            alert_id=alert.alert_id,
            classification=Classification.FALSE_POSITIVE,
            confidence=0.96,
            reasoning="Approved vulnerability-scanner activity matches a known administrative profile.",
            recommended_action="Suppress and retain the approved scanner exception.",
            mitre_tactics=[],
        )

    if any(term in text for term in update_terms) and any(
        term in text for term in ("signed", "trusted", "microsoft", "vendor")
    ):
        return TriageDecision(
            alert_id=alert.alert_id,
            classification=Classification.FALSE_POSITIVE,
            confidence=0.95,
            reasoning="Traffic matches trusted vendor update behavior.",
            recommended_action="Suppress and monitor the allowlisted update channel.",
            mitre_tactics=[],
        )

    if any(term in text for term in threat_terms):
        tactics = ["TA0001 - Initial Access"] if "phish" in text else []
        return TriageDecision(
            alert_id=alert.alert_id,
            classification=Classification.TRUE_POSITIVE,
            confidence=0.86,
            reasoning="Alert contains high-signal indicators associated with malicious activity.",
            recommended_action="Escalate to the SOC incident response workflow.",
            mitre_tactics=tactics,
            mitre_technique_id="T1110" if "brute force" in text else (
                "T1566.001" if "phish" in text else "T1048.003"
            ),
            severity_justification=(
                "High-signal malicious indicators and suspicious activity pattern "
                "support immediate SOC escalation."
            ),
            remediation_steps=[
                "Contain or block the suspicious source and affected asset.",
                "Collect authentication, endpoint, and network evidence.",
                "Escalate to incident response and begin scope assessment.",
            ],
        )

    return TriageDecision(
        alert_id=alert.alert_id,
        classification=Classification.FALSE_POSITIVE,
        confidence=0.50,
        reasoning="No deterministic high-confidence threat or approved administrative pattern was found.",
        recommended_action="Route to an analyst for manual review.",
        mitre_tactics=[],
    )


# ──────────────────────────────────────────────────────────────────────
#  Mock Classifier (deterministic, no API key needed)
# ──────────────────────────────────────────────────────────────────────

def mock_classify(
    alert: RawAlert,
    feedback_store: Optional[FeedbackStore] = None,
) -> TriageDecision:
    """
    Deterministic mock classifier that simulates LLM behavior.

    Intentionally MISCLASSIFIES Alert ALERT-SCAN03 (Port Scan) as TP
    on the first pass (no feedback). When feedback exists for that
    alert type, it corrects itself — demonstrating the feedback loop.
    """
    # Check if we have analyst feedback for this specific alert
    if feedback_store and feedback_store.has_feedback(alert.alert_id):
        fb = feedback_store.get_feedback(alert.alert_id)
        return TriageDecision(
            alert_id=alert.alert_id,
            classification=fb.corrected_classification,
            confidence=0.95,
            reasoning=(
                f"Analyst correction applied. Original: {fb.original_classification.value}, "
                f"Corrected: {fb.corrected_classification.value}. "
                f"Analyst notes: {fb.feedback_notes}"
            ),
            recommended_action=(
                "Suppress — Analyst verified as benign"
                if fb.corrected_classification == Classification.FALSE_POSITIVE
                else "Escalate — Analyst confirmed threat"
            ),
            mitre_tactics=[],
            analyst_notes=fb.feedback_notes,
        )

    # Check for few-shot examples from similar alert types
    if feedback_store:
        examples = feedback_store.get_relevant_examples(alert.alert_type)
        if examples:
            # Learn from analyst corrections on similar alerts
            latest = examples[0]
            return TriageDecision(
                alert_id=alert.alert_id,
                classification=latest.corrected_classification,
                confidence=0.88,
                reasoning=(
                    f"Few-shot learning from analyst correction on similar "
                    f"'{alert.alert_type}' alert. Analyst previously corrected "
                    f"{latest.original_classification.value} → "
                    f"{latest.corrected_classification.value}. "
                    f"Applying learned pattern: {latest.feedback_notes}"
                ),
                recommended_action=(
                    "Suppress — Pattern matches known benign activity"
                    if latest.corrected_classification == Classification.FALSE_POSITIVE
                    else "Escalate — Pattern matches confirmed threat"
                ),
                mitre_tactics=[],
            )

    # ── Default Mock Classifications (Pass 1, no feedback) ──────────

    mock_decisions: dict[str, TriageDecision] = {

        "ALERT-BRUTE01": TriageDecision(
            alert_id="ALERT-BRUTE01",
            classification=Classification.TRUE_POSITIVE,
            confidence=0.96,
            reasoning=(
                "1. SOURCE: External IP 185.220.101.42 — AbuseIPDB score 98%, "
                "known Tor exit node in Frankfurt, DE.\n"
                "2. BEHAVIOR: 847 failed SSH attempts in 5 min with username "
                "enumeration (root, admin, ubuntu) — classic brute-force pattern.\n"
                "3. CONTEXT: No approved change ticket, external origin.\n"
                "4. MITRE: T1110.001 (Brute Force: Password Guessing).\n"
                "VERDICT: HIGH CONFIDENCE TRUE POSITIVE."
            ),
            recommended_action=(
                "IMMEDIATE: Block source IP at perimeter firewall. "
                "Escalate to IR team. Check target host 10.0.1.15 for "
                "successful logins. Enable account lockout policy."
            ),
            mitre_tactics=[
                "TA0006 - Credential Access",
                "T1110.001 - Brute Force: Password Guessing",
            ],
            mitre_technique_id="T1110.001",
            severity_justification="847 failed SSH attempts from a Tor exit node with a 98% abuse score indicate a high-confidence credential attack.",
            remediation_steps=[
                "Block the source IP at the perimeter firewall.",
                "Review the target host for successful logins and persistence.",
                "Escalate to incident response and enforce account protections.",
            ],
        ),

        "ALERT-PHISH02": TriageDecision(
            alert_id="ALERT-PHISH02",
            classification=Classification.TRUE_POSITIVE,
            confidence=0.94,
            reasoning=(
                "1. SOURCE: External mail relay (mail-relay.xyz), not company infra.\n"
                "2. BEHAVIOR: CEO impersonation with lookalike domain (company-corp.co "
                "vs .com). Password-protected ZIP with macro-enabled Excel — classic "
                "payload delivery.\n"
                "3. CONTEXT: SPF FAIL, DKIM FAIL, DMARC REJECT — all authentication "
                "checks failed. VirusTotal: 23 detections.\n"
                "4. MITRE: T1566.001 (Phishing: Spearphishing Attachment).\n"
                "VERDICT: HIGH CONFIDENCE TRUE POSITIVE."
            ),
            recommended_action=(
                "QUARANTINE the email immediately. Block sender domain "
                "company-corp.co. Alert CFO not to open any attachments. "
                "Scan CFO workstation for IOCs. Report to anti-phishing team."
            ),
            mitre_tactics=[
                "TA0001 - Initial Access",
                "T1566.001 - Phishing: Spearphishing Attachment",
            ],
            mitre_technique_id="T1566.001",
            severity_justification="Failed email authentication, executive impersonation, and a malicious attachment indicate an active phishing attempt.",
            remediation_steps=[
                "Quarantine the message and block the sender infrastructure.",
                "Scan recipient endpoints and collect attachment indicators.",
                "Escalate to incident response and notify impacted users.",
            ],
        ),

        # ⚠️ INTENTIONAL MISCLASSIFICATION — This is a FALSE POSITIVE
        # but the mock classifier (without feedback) says TP.
        # This demonstrates why the feedback loop is needed.
        "ALERT-SCAN03": TriageDecision(
            alert_id="ALERT-SCAN03",
            classification=Classification.TRUE_POSITIVE,  # ← WRONG!
            confidence=0.62,
            reasoning=(
                "1. SOURCE: Internal IP 10.0.50.10 — scanning entire /24 subnet.\n"
                "2. BEHAVIOR: Full TCP SYN scan of 65,535 ports across 254 hosts — "
                "aggressive reconnaissance pattern.\n"
                "3. CONTEXT: Activity could be a vulnerability scanner, but the "
                "volume is concerning. Unable to verify change ticket.\n"
                "4. MITRE: T1046 (Network Service Discovery).\n"
                "VERDICT: MODERATE CONFIDENCE — flagging as TP for analyst review."
            ),
            recommended_action=(
                "INVESTIGATE: Verify if source IP 10.0.50.10 is a registered "
                "scanner. Check change management for approved scan windows. "
                "If unauthorized, isolate the host immediately."
            ),
            mitre_tactics=[
                "TA0007 - Discovery",
                "T1046 - Network Service Discovery",
            ],
            mitre_technique_id="T1046",
            severity_justification="A full-subnet, full-port scan is high-volume reconnaissance pending verification of authorization.",
            remediation_steps=[
                "Verify the scanner registration and approved change ticket.",
                "Monitor scanned assets for follow-on exploitation activity.",
                "Escalate to the SOC lead if authorization cannot be confirmed.",
            ],
        ),

        "ALERT-DNSEX04": TriageDecision(
            alert_id="ALERT-DNSEX04",
            classification=Classification.TRUE_POSITIVE,
            confidence=0.92,
            reasoning=(
                "1. SOURCE: Internal workstation 10.0.3.77 — potentially compromised.\n"
                "2. BEHAVIOR: 2,340 DNS TXT queries in 10 min to high-entropy "
                "subdomains of newly-registered domain (3 days old). Average "
                "subdomain length 48 chars — classic DNS tunneling signature.\n"
                "3. CONTEXT: ML anomaly score 0.96. Anonymous registrar. No "
                "business justification for this traffic pattern.\n"
                "4. MITRE: T1048.003 (Exfiltration Over Alternative Protocol: DNS).\n"
                "VERDICT: HIGH CONFIDENCE TRUE POSITIVE."
            ),
            recommended_action=(
                "CRITICAL: Isolate workstation 10.0.3.77 from network. "
                "Block domain data-x7k9.top at DNS resolver. Capture full "
                "DNS query log for forensic analysis. Check host for malware. "
                "Assess data exposure scope."
            ),
            mitre_tactics=[
                "TA0010 - Exfiltration",
                "T1048.003 - Exfiltration Over Alternative Protocol: DNS",
                "TA0011 - Command and Control",
            ],
            mitre_technique_id="T1048.003",
            severity_justification="Thousands of high-entropy DNS TXT queries to a newly registered domain strongly indicate covert data exfiltration.",
            remediation_steps=[
                "Isolate the affected workstation from the network.",
                "Block the domain and preserve DNS and endpoint telemetry.",
                "Escalate to incident response for malware and exposure analysis.",
            ],
        ),

        "ALERT-WDEF05": TriageDecision(
            alert_id="ALERT-WDEF05",
            classification=Classification.FALSE_POSITIVE,
            confidence=0.97,
            reasoning=(
                "1. SOURCE: Internal endpoint 10.0.4.22.\n"
                "2. BEHAVIOR: HTTPS connection to Microsoft Update CDN "
                "(13.107.4.50 / definitionupdates.microsoft.com).\n"
                "3. CONTEXT: Process is MsMpEng.exe (Windows Defender), "
                "connecting to verified Microsoft infrastructure with "
                "valid TLS certificate. Standard signature update behavior.\n"
                "4. MITRE: Not applicable — routine update traffic.\n"
                "VERDICT: HIGH CONFIDENCE FALSE POSITIVE — benign update."
            ),
            recommended_action=(
                "SUPPRESS this alert. Add definitionupdates.microsoft.com "
                "to the allowlist. Consider tuning the 'outbound connection "
                "to external IP' rule to exclude known Microsoft CDN ranges."
            ),
            mitre_tactics=[],
            mitre_technique_id=None,
            severity_justification="Trusted Microsoft Defender update traffic is benign administrative activity.",
            remediation_steps=[],
        ),
    }

    decision = mock_decisions.get(alert.alert_id)
    if decision:
        return decision

    # Fallback for unknown alerts
    return TriageDecision(
        alert_id=alert.alert_id,
        classification=Classification.FALSE_POSITIVE,
        confidence=0.50,
        reasoning="Unknown alert — insufficient context for classification.",
        recommended_action="Escalate to senior analyst for manual review.",
        mitre_tactics=[],
    )


# ──────────────────────────────────────────────────────────────────────
#  Response Parser
# ──────────────────────────────────────────────────────────────────────

def _parse_llm_response(alert_id: str, response_text: str) -> TriageDecision:
    """
    Parse the LLM's JSON response into a TriageDecision.

    Handles common LLM response quirks (markdown code fences, extra text).
    """
    # Strip markdown code fences if present
    text = response_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last lines (code fences)
        text = "\n".join(lines[1:-1]) if len(lines) > 2 else text

    # Try to extract JSON from the response
    try:
        # Find the first { and last }
        start = text.index("{")
        end = text.rindex("}") + 1
        json_str = text[start:end]
        data = json.loads(json_str)

        return TriageDecision(
            alert_id=alert_id,
            classification=Classification(data.get("classification", "FP")),
            confidence=float(data.get("confidence", 0.5)),
            reasoning=data.get("reasoning", "No reasoning provided"),
            recommended_action=data.get("recommended_action", "Review manually"),
            mitre_tactics=data.get("mitre_tactics", []),
            mitre_technique_id=data.get("mitre_technique_id"),
            severity_justification=data.get("severity_justification", ""),
            remediation_steps=data.get("remediation_steps", []),
        )
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        # Fallback: return a low-confidence decision
        return TriageDecision(
            alert_id=alert_id,
            classification=Classification.FALSE_POSITIVE,
            confidence=0.30,
            reasoning=f"Failed to parse LLM response: {e}. Raw: {response_text[:200]}",
            recommended_action="Manual review required — LLM response unparseable.",
            mitre_tactics=[],
        )
