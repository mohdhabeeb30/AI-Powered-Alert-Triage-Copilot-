# AI-Powered Alert Triage Copilot

An open-source security operations workflow for classifying SIEM, IDS, EDR, and cloud security alerts as **True Positive (TP)** or **False Positive (FP)**. The copilot combines Google Agent Development Kit (ADK) 2.0, Gemini 2.0 Flash, deterministic fallback rules, SQLite persistence, human analyst feedback, and a Streamlit incident-response dashboard.

The system is designed for SOC-L2 workflows where fast, explainable triage matters: suspicious activity is enriched with MITRE ATT&CK context and immediate remediation steps, while approved scanners and trusted update traffic can be deflected without silently losing the decision history.

## Architecture

```text
 Raw Security JSON Logs
        |
        v
+-------------------------+
| FastAPI Gateway         |
| /api/v1/alerts/triage   |
| /api/v1/feedback        |
| /api/v1/metrics         |
+------------+------------+
         |
         v
+-------------------------+
| Google ADK 2.0          |
| Gemini 2.0 Flash        |
| SOC-L2 system prompt   |
+------------+------------+
         |
     API key, quota,
     or token failure?
         |
     +-----+-----+
     |           |
     v           v
  Live LLM    Quota Fallback Switch
          Deterministic Rules
     \           /
      \         /
       v       v
+-------------------------+
| TriageDecision           |
| TP/FP + confidence       |
| MITRE technique ID       |
| severity justification   |
| remediation checklist    |
+------------+------------+
         |
         v
+-------------------------+
| SQLite Persistence Layer |
| raw_alerts               |
| triage_decisions         |
| analyst_feedback         |
+------------+------------+
         |
         +----------------------+
         |                      |
         v                      v
  Few-shot Feedback Matrix   Streamlit Incident Response UI
  Analyst corrections       Analytics | Feedback | Playground
```

### Request and persistence flow

1. A `RawAlert` is validated with Pydantic v2 at the FastAPI boundary.
2. The gateway retrieves relevant analyst corrections from SQLite.
3. The async triage engine calls ADK when live mode is enabled and an API connection is available.
4. Missing credentials, invalid configuration, quota exhaustion, rate limits, resource exhaustion, token limits, or malformed model output trigger a logged deterministic fallback instead of an unhandled failure.
5. Every result is validated as a `TriageDecision` and appended to the SQLite decision history.
6. The Streamlit dashboard reads live metrics, submits analyst overrides, and displays enriched TP response actions.

## Core Value: Feedback That Reduces Alert Fatigue

The copilot includes a human-in-the-loop feedback loop rather than treating the first model decision as final. When an analyst corrects a decision, the correction is stored with the alert type, original classification, corrected classification, and rationale. Future prompts receive those records as a labeled few-shot matrix.

Example feedback context:

```text
| Alert Type: Port Scan | Source IP: 10.0.50.10 |
| Model: TP | Analyst: FP |
| Rationale: Registered Nessus scanner operating during an approved change window |
```

This gives the live agent and deterministic fallback a durable operational memory for patterns such as:

- Approved Nessus, Qualys, or Tenable vulnerability scans
- Scheduled maintenance and authorized change windows
- Trusted Microsoft, Google, or Amazon update traffic
- Repeated high-confidence brute force, phishing, or DNS exfiltration activity

The included demonstration shows the measurable effect of analyst review:

| Metric | Before Feedback | After Feedback |
|---|---:|---:|
| Precision | 75.0% | **100.0%** |
| Recall | 100.0% | 100.0% |
| F1-Score | 85.7% | **100.0%** |
| Deflection Rate | 50.0% | **100.0%** |

The precision improvement comes from correcting the approved Nessus scan from TP to FP and applying that lesson during the second triage pass.

## Threat Intelligence Integration

Every True Positive must include strict CTI enrichment in the Pydantic `TriageDecision` contract:

- **MITRE ATT&CK Technique ID**: The primary technique associated with the observed behavior, such as `T1110.001` for password guessing, `T1566.001` for spearphishing attachment, or `T1048.003` for DNS-based exfiltration.
- **Severity Justification**: A concise evidence-based explanation connecting the alert signals to the operational severity.
- **Three Remediation Steps**: Immediate actions for the SOC team, such as containment, evidence collection, blocking indicators, endpoint review, and incident-response escalation.

The schema rejects incomplete TP decisions. False Positives retain the normal suppression and monitoring response without requiring threat remediation fields.

In the Streamlit **Triage Playground**, a TP response displays:

1. A high-visibility threat banner.
2. The MITRE technique ID.
3. The severity justification.
4. Three interactive checkboxes for tracking immediate remediation progress.

## API Endpoints

The FastAPI service listens on `127.0.0.1:8000` by default.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/alerts/triage?live=false` | Validate, classify, and persist a raw alert |
| `POST` | `/api/v1/feedback` | Persist an analyst correction for a prior decision |
| `GET` | `/api/v1/metrics` | Compute live Precision, Recall, F1, and Deflection Rate |
| `GET` | `/health` | Check API availability |

The triage endpoint accepts a `RawAlert` JSON object. Set `live=true` to attempt Gemini through ADK; the backend automatically falls back to deterministic classification when live analysis is unavailable.

## Quick Start

### 1. Create and activate the virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the FastAPI backend on port 8000

From the repository root:

```bash
uvicorn alert_triage_copilot.main:app --host 127.0.0.1 --port 8000 --reload
```

The SQLite database is initialized automatically as `triage_copilot.db`.

### 4. Start the Streamlit dashboard on port 8501

Open a second terminal, activate the same virtual environment, and run:

```bash
streamlit run app.py --server.port 8501
```

Open [http://localhost:8501](http://localhost:8501). The dashboard validates the FastAPI gateway before rendering. If port 8000 is unavailable, it displays a clear backend-offline warning.

### 5. Optional live Gemini mode

Set the Google API key before starting the backend or running the demo:

```bash
export GOOGLE_API_KEY="your-google-api-key"
export ADK_MODEL="gemini-2.0-flash"
```

Live mode is optional. The deterministic mock classifier and full dashboard workflow work without an API key.

## Run the Demonstration

```bash
python run_demo.py
```

The demonstration covers ingestion, first-pass triage, metrics, analyst correction, feedback-enhanced re-triage, and before/after comparison. It includes brute force, phishing, Nessus scanning, DNS exfiltration, and Windows Defender update scenarios.

## Project Structure

```text
.
├── app.py                              # Streamlit incident-response dashboard
├── run_demo.py                         # End-to-end mock lifecycle
├── requirements.txt                    # Runtime dependencies
├── triage_copilot.db                   # SQLite runtime database
└── alert_triage_copilot/
    ├── agent.py                        # ADK agent, parser, fallback classifier
    ├── db.py                           # SQLAlchemy engine, sessions, migrations
    ├── evaluation.py                   # Precision/Recall/F1/Deflection engine
    ├── feedback_loop.py                # Persistent analyst feedback and few-shots
    ├── main.py                         # FastAPI application and API endpoints
    ├── mock_data.py                    # Demonstration alerts and labels
    ├── models.py                       # SQLAlchemy persistence models
    ├── schemas.py                      # Pydantic v2 API contracts and CTI rules
    └── triage_engine.py                # Async single and batch orchestration
```

## Security and Operations Notes

- Keep `GOOGLE_API_KEY` in the environment or a secret manager; never commit it to source control.
- Configure browser origins with `TRIAGE_CORS_ORIGINS` for deployments instead of relying on the development wildcard.
- Treat deterministic fallback classifications as resilient decision support and retain analyst review for ambiguous alerts.
- Protect `triage_copilot.db` with appropriate filesystem permissions because it contains alert payloads, analyst identifiers, and response history.
- The included SQLite setup is suitable for local evaluation. Production deployments should use managed database backups, controlled migrations, authentication, authorization, and audit-log retention.

## License

MIT License. See the project distribution for the complete license terms.
